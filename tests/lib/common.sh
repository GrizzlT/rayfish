# Shared helpers for the rayfish e2e / benchmark test orchestrators.
# Sourced (not executed) by each scenario's run.sh after it sets DIR/ROOT/SERVERS.
# Provides SSH plumbing, PASS/FAIL accounting, and host-lifecycle helpers
# (wait-for-ssh, state reset, deploy, daemon-up) so the run.sh scripts contain
# only their scenario-specific steps.

KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes)

# PASS/FAIL accounting. FAILS is read by summary().
FAILS=0
pass(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# summary : print the final tally and exit non-zero if any check failed.
summary(){
  step "summary"
  if [[ "$FAILS" -eq 0 ]]; then
    printf '\033[32mALL CHECKS PASSED\033[0m\n'; exit 0
  else
    printf '\033[31m%d CHECK(S) FAILED\033[0m\n' "$FAILS"; exit 1
  fi
}

# on <ip> <command-string> : run a shell command on a host as root.
# -n: never read stdin, so calling `on` inside a `while read` loop can't eat it.
on(){ local ip="$1"; shift; ssh -n "${SSH_OPTS[@]}" -i "$KEY" "root@$ip" "$*"; }

# strip : remove ANSI colour codes from rayfish CLI output (stdin -> stdout).
strip(){ sed -r 's/\x1B\[[0-9;]*[mGKH]//g'; }

# own_ip <status-text> : extract a node's own VPN IPv4 (100.64.0.0/10 CGNAT range).
own_ip(){ echo "$1" | grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+' | head -1; }

# peer_host <status-text> : first peer row's `<host>.<net>.ray` hostname label.
peer_host(){ echo "$1" | grep -E '●|○' | grep -oE '[a-z0-9-]+\.[a-z0-9-]+\.ray' | head -1 | cut -d. -f1; }

# ping_loss <from-ip> <target-ip> : echo the packet-loss percentage (number only).
ping_loss(){ on "$1" "ping -c 3 -W 2 $2" 2>&1 | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+'; }

# png <from-ip> <target-ip> <label> : PASS if 0% loss, FAIL otherwise.
png(){
  local loss; loss="$(ping_loss "$1" "$2")"
  if [[ "${loss:-100}" == "0" ]]; then pass "ping $3"; else fail "ping $3 (loss=${loss:-?}%)"; fi
}

# server_ip <servers-file> <label> : echo the public ip for a label in a
# `id ip label zone` .servers file. Avoids bash-3.2 associative arrays.
server_ip(){
  local f="$1" want="$2" id ip label zone
  while read -r id ip label zone; do
    [[ "${label:-}" == "$want" ]] && { echo "$ip"; return 0; }
  done < "$f"
  return 1
}

# wait_all_ssh <ip...> : block until every host accepts SSH; abort on timeout.
wait_all_ssh(){
  local ip
  for ip in "$@"; do
    local ok=0 _
    for _ in $(seq 1 60); do on "$ip" true 2>/dev/null && { ok=1; break; }; sleep 5; done
    if [[ "$ok" == 1 ]]; then pass "ssh reachable ($ip)"; else fail "ssh ($ip) unreachable"; echo "aborting"; exit 1; fi
  done
}

# seed_known_hosts <ip...> : pre-seed ~/.ssh/known_hosts so `just deploy` (which
# uses the default known_hosts) doesn't block on an interactive host-key prompt.
seed_known_hosts(){
  local h
  for h in "$@"; do ssh-keyscan -T 10 "$h" >> ~/.ssh/known_hosts 2>/dev/null || true; done
}

# reset_state <ip...> : clean-slate the daemon (stop + wipe ~/.config/rayfish) so
# runs are reproducible on already-used servers. Set KEEP_STATE=1 to skip.
reset_state(){
  [[ "${KEEP_STATE:-0}" == "1" ]] && return 0
  step "reset rayfish state on all hosts (KEEP_STATE=1 to skip)"
  local h
  for h in "$@"; do
    on "$h" 'systemctl stop rayfish 2>/dev/null; rm -rf /root/.config/rayfish' && echo "   reset $h"
  done
}

# deploy_all <root> <ip...> : cross-build + rsync + ray up on each host; abort on failure.
deploy_all(){
  local root="$1"; shift
  step "deploy ray to all hosts (cross build + rsync + ray up)"
  local ip
  for ip in "$@"; do
    echo ">> just deploy $ip"
    if ( cd "$root" && just deploy "$ip" ); then pass "deploy $ip"; else fail "deploy $ip"; echo "aborting"; exit 1; fi
  done
}

# wait_daemons <ip...> : give daemons a moment to settle, then confirm `ray status` responds.
wait_daemons(){
  sleep 5
  local ip
  for ip in "$@"; do
    if on "$ip" 'ray status' >/dev/null 2>&1; then pass "daemon up on $ip"; else fail "daemon not responding on $ip"; fi
  done
}

# send_recv <from-ip> <to-ip> <to-peer-hostname> <label> : ray send a 1MiB random
# file and verify the sha256 round-trips after `ray files accept`. SR_PREFIX sets
# the temp-file path prefix (default /tmp/ray_e2e).
send_recv(){
  local from="$1" to="$2" peer="$3" label="$4"
  local pfx="${SR_PREFIX:-/tmp/ray_e2e}"
  on "$from" "head -c 1048576 /dev/urandom > ${pfx}_src.bin; sha256sum ${pfx}_src.bin | cut -d' ' -f1 > ${pfx}_src.sha"
  local src_sha; src_sha="$(on "$from" "cat ${pfx}_src.sha")"
  on "$from" "ray send ${pfx}_src.bin $peer" 2>&1 | strip | sed 's/^/      send| /'
  # `ray files` rows are `<id> <from> <size> <file> …` with a numeric id; the
  # header row's first column is the literal "id", so match a numeric id.
  local fid=""
  for _ in $(seq 1 12); do
    fid="$(on "$to" 'ray files' 2>/dev/null | strip | awk '$1 ~ /^[0-9]+$/ {print $1; exit}')"
    [[ -n "$fid" ]] && break
    sleep 3
  done
  if [[ -z "$fid" ]]; then fail "$label: no incoming file offer on receiver"; return; fi
  on "$to" "rm -rf ${pfx}_recv && mkdir -p ${pfx}_recv && ray files accept $fid --output ${pfx}_recv" 2>&1 | strip | sed 's/^/      recv| /'
  local dst_sha=""
  for _ in $(seq 1 10); do
    dst_sha="$(on "$to" "f=\$(find ${pfx}_recv -type f | head -1); [ -n \"\$f\" ] && sha256sum \"\$f\" | cut -d' ' -f1")"
    [[ -n "$dst_sha" ]] && break
    sleep 2
  done
  if [[ -n "$dst_sha" && "$dst_sha" == "$src_sha" ]]; then
    pass "$label (sha ${src_sha:0:12}… verified)"
  else
    fail "$label (sent ${src_sha:0:12}… got ${dst_sha:0:12}…)"
  fi
}
