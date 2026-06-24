#!/usr/bin/env bash
# Device-cert 3-peer e2e test orchestrator.
#
# Topology (see docs/superpowers/specs/2026-06-24-device-cert-e2e-design.md):
#   srv-a  identity U   primary device + coordinator of a trusted network
#   srv-b  identity U   paired into A's identity via a DeviceCert (ray pair)
#   srv-c  identity V   independent third peer
#
# Proves that C can ping + ray-send to the U identity regardless of which
# physical device (A or B) backs it, and that A/B share one user identity/IP.
#
# Reads tests/e2e/.servers (written by provision.sh). Does NOT modify infra.
# Re-runnable: pairing/join steps tolerate "already done".
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
SERVERS="$DIR/.servers"
KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=10 -o LogLevel=ERROR -o BatchMode=yes)

[[ -f "$SERVERS" ]] || { echo "No $SERVERS — run tests/e2e/provision.sh first"; exit 1; }

A=""; B=""; C=""
while read -r id ip label zone; do
  case "${label:-}" in
    srv-a) A="$ip" ;;
    srv-b) B="$ip" ;;
    srv-c) C="$ip" ;;
  esac
done < "$SERVERS"
[[ -n "$A" && -n "$B" && -n "$C" ]] || { echo "missing srv-a/b/c in $SERVERS"; exit 1; }

FAILS=0
pass(){ printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail(){ printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# on <ip> <command-string> : run a shell command on a host as root.
# -n: never read stdin, so calling `on` inside a `while read` loop can't eat it.
on(){ local ip="$1"; shift; ssh -n "${SSH_OPTS[@]}" -i "$KEY" "root@$ip" "$*"; }
# strip ANSI colour codes from rayfish CLI output.
strip(){ sed -r 's/\x1B\[[0-9;]*[mGKH]//g'; }

# ---------------------------------------------------------------------------
step "0. wait for SSH on all hosts"
wait_ssh(){ local ip="$1"; for _ in $(seq 1 60); do on "$ip" true 2>/dev/null && return 0; sleep 5; done; return 1; }
for pair in "srv-a $A" "srv-b $B" "srv-c $C"; do
  set -- $pair
  if wait_ssh "$2"; then pass "ssh $1 ($2)"; else fail "ssh $1 ($2) unreachable"; echo "aborting"; exit 1; fi
done
# Seed ~/.ssh/known_hosts so `just deploy` (which uses the default known_hosts)
# doesn't block on an interactive host-key prompt.
for h in "$A" "$B" "$C"; do ssh-keyscan -T 10 "$h" >> ~/.ssh/known_hosts 2>/dev/null || true; done

# ---------------------------------------------------------------------------
# Clean-slate reset so the script is reproducible on already-used servers:
# stop the daemon and wipe its state (identity, networks, certs, blobs). Each
# run then starts from scratch — fresh identities, no leftover `e2e` network.
# Set KEEP_STATE=1 to skip (e.g. to re-run against an existing network).
if [[ "${KEEP_STATE:-0}" != "1" ]]; then
  step "0b. reset rayfish state on all hosts (KEEP_STATE=1 to skip)"
  for h in "$A" "$B" "$C"; do
    on "$h" 'systemctl stop rayfish 2>/dev/null; rm -rf /root/.config/rayfish' && echo "   reset $h"
  done
fi

# ---------------------------------------------------------------------------
step "1. deploy ray to all hosts (cross build + rsync + ray up)"
for pair in "srv-a $A" "srv-b $B" "srv-c $C"; do
  set -- $pair
  echo ">> just deploy $2 ($1)"
  if ( cd "$ROOT" && just deploy "$2" ); then pass "deploy $1"; else fail "deploy $1"; echo "aborting"; exit 1; fi
done
# give daemons a moment to settle
sleep 5
for pair in "srv-a $A" "srv-b $B" "srv-c $C"; do
  set -- $pair
  if on "$2" 'ray status' >/dev/null 2>&1; then pass "daemon up on $1"; else fail "daemon not responding on $1"; fi
done

# ---------------------------------------------------------------------------
step "2. pair srv-b into srv-a's identity (device cert)"
A_ENDPOINT="$(on "$A" 'ray status' | strip | awk '/endpoint/{print $2}')"
echo "   srv-a endpoint/identity: $A_ENDPOINT"

# `ray pair` on A arms the daemon's pairing accept loop and prints a ticket.
TICKET="$(on "$A" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
if [[ -z "$TICKET" ]]; then fail "could not obtain pairing ticket from srv-a"; else
  echo "   ticket: ${TICKET:0:16}…"
  # B accepts; retry a few times in case it races the arm on A.
  B_PAIR=""
  for _ in 1 2 3 4 5; do
    B_PAIR="$(on "$B" "ray pair $TICKET" | strip)"
    echo "$B_PAIR" | grep -qi 'Paired successfully' && break
    sleep 3
    TICKET="$(on "$A" 'ray pair' | strip | awk -F': ' '/Pairing ticket/{print $2}' | tr -d ' ')"
  done
  echo "$B_PAIR" | sed 's/^/   | /'
  B_USER="$(echo "$B_PAIR" | awk -F': ' '/User identity/{print $2}' | tr -d ' ')"
  if echo "$B_PAIR" | grep -qi 'Paired successfully'; then
    pass "srv-b paired"
    if [[ -n "$B_USER" && "$B_USER" == "$A_ENDPOINT" ]]; then
      pass "srv-b user identity == srv-a identity ($B_USER)"
    else
      fail "srv-b user identity ($B_USER) != srv-a identity ($A_ENDPOINT)"
    fi
  else
    fail "srv-b pairing did not complete"
  fi
fi

# `ray pair` stores the device cert to disk but does NOT refresh the running
# daemon's in-memory copy (self.device_cert). A join in the same session would
# therefore omit the cert and the coordinator would record srv-b as an
# independent identity instead of user U. Restart srv-b so it loads the cert
# from disk before joining. (See run notes — this restart works around a real
# product bug.)
echo ">> restarting srv-b daemon so it loads the new device cert before joining"
on "$B" 'systemctl restart rayfish' >/dev/null 2>&1
for _ in $(seq 1 20); do on "$B" 'ray status' >/dev/null 2>&1 && break; sleep 3; done
pass "srv-b daemon restarted (device cert loaded)"

# ---------------------------------------------------------------------------
step "3. create trusted network on srv-a + mint hostname-bound invites"
NET=e2e
CREATE="$(on "$A" "ray create --trusted --name $NET --hostname srv-a" | strip)"
echo "$CREATE" | sed 's/^/   | /'
ROOM="$(echo "$CREATE" | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1)"
if [[ -n "$ROOM" ]]; then pass "network '$NET' created (room ${ROOM:0:12}…)"; else
  # maybe it already exists from a previous run
  on "$A" "ray status" | strip | grep -q "$NET" && { pass "network '$NET' already exists"; } || fail "network create failed"
fi

mint_invite(){ # mint_invite <hostname>  -> echoes invite code
  # `--hostname` belongs to the (default) `create` subcommand, so name it explicitly.
  on "$A" "ray invite $NET create --hostname $1" | strip \
    | sed -n 's/.*ray join \([A-Za-z0-9]\{20,\}\).*/\1/p' | head -1
}
INV_B="$(mint_invite srv-b)"
INV_C="$(mint_invite srv-c)"
[[ -n "$INV_B" ]] && pass "invite for srv-b (${INV_B:0:12}…)" || fail "no invite for srv-b"
[[ -n "$INV_C" ]] && pass "invite for srv-c (${INV_C:0:12}…)" || fail "no invite for srv-c"

# ---------------------------------------------------------------------------
step "4. srv-b and srv-c join the trusted network"
if [[ -n "$INV_B" ]]; then
  on "$B" "ray join $INV_B --allow-trusted" 2>&1 | strip | sed 's/^/   b| /'
fi
if [[ -n "$INV_C" ]]; then
  on "$C" "ray join $INV_C --allow-trusted" 2>&1 | strip | sed 's/^/   c| /'
fi
# Backstop: admit anything queued (invites should auto-admit on a trusted net).
sleep 3
REQ="$(on "$A" "ray requests $NET" 2>/dev/null | strip || true)"
echo "$REQ" | grep -qiE '[0-9a-f]{6,}' && { echo "   pending requests found, accepting:"; echo "$REQ" | sed 's/^/   r| /'; \
  echo "$REQ" | awk '/^ /{print $1}' | while read -r rid; do [[ -n "$rid" ]] && on "$A" "ray accept $NET $rid" | strip | sed 's/^/   a| /'; done; }

# ---------------------------------------------------------------------------
step "5. wait for roster convergence (A, B, C all visible)"
converged=0
for _ in $(seq 1 18); do  # up to ~90s
  SA="$(on "$A" 'ray status' | strip)"
  # coordinator should list both srv-b and srv-c as online peers.
  if echo "$SA" | grep -q 'srv-b\.' && echo "$SA" | grep -q 'srv-c\.'; then converged=1; break; fi
  sleep 5
done
SA="$(on "$A" 'ray status' | strip)"; SB="$(on "$B" 'ray status' | strip)"; SC="$(on "$C" 'ray status' | strip)"
echo "---- srv-a status ----"; echo "$SA" | sed 's/^/   a| /'
echo "---- srv-b status ----"; echo "$SB" | sed 's/^/   b| /'
echo "---- srv-c status ----"; echo "$SC" | sed 's/^/   c| /'
[[ "$converged" == 1 ]] && pass "roster converged (coordinator sees B+C online)" || fail "roster did not converge within timeout"

# Extract each node's own VPN IPv4 (printed in parens on its net line). The
# CGNAT range is 100.64.0.0/10, so the second octet spans 64–127 — match any.
own_ip(){ echo "$1" | grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+' | head -1; }
A_IP="$(own_ip "$SA")"; B_IP="$(own_ip "$SB")"; C_IP="$(own_ip "$SC")"
echo "   A_IP=$A_IP  B_IP=$B_IP  C_IP=$C_IP"

# ---------------------------------------------------------------------------
step "6. identity assertions"
# Rayfish derives the VPN IP from the per-device EndpointId (not the user
# identity), so paired devices share a USER IDENTITY but get DISTINCT IPs
# (Tailscale-style). Assert all three IPs are present and pairwise distinct.
if [[ -n "$A_IP" && -n "$B_IP" && -n "$C_IP" \
      && "$A_IP" != "$B_IP" && "$A_IP" != "$C_IP" && "$B_IP" != "$C_IP" ]]; then
  pass "three distinct per-device IPs (srv-a=$A_IP srv-b=$B_IP srv-c=$C_IP)"
else
  fail "expected three distinct IPs (srv-a=$A_IP srv-b=$B_IP srv-c=$C_IP)"
fi
# Network-level device-cert recognition: the coordinator must resolve srv-b's
# transport key to srv-a's USER IDENTITY (shown as a `user:<prefix>` tag).
UPREFIX="$(echo "$A_ENDPOINT" | cut -c1-10)"
if echo "$SA" | grep 'srv-b' | grep -q "user:$UPREFIX"; then
  pass "coordinator resolves srv-b to srv-a's user identity (user:${UPREFIX}…) — device cert recognized"
else
  fail "coordinator does not tag srv-b as user:$UPREFIX (device cert not recognized at join)"
fi

# ---------------------------------------------------------------------------
step "7. reachability — ping over the TUN (both directions)"
png(){ # png <from-ip> <target-ip> <label>
  local out; out="$(on "$1" "ping -c 3 -W 2 $2" 2>&1)"
  if echo "$out" | grep -qE ' 0% packet loss| [123] received'; then pass "ping $3"; else fail "ping $3"; echo "$out" | tail -2 | sed 's/^/      /'; fi
}
# srv-c must reach BOTH physical devices backing identity U:
[[ -n "$C_IP" && -n "$A_IP" ]] && png "$C" "$A_IP" "srv-c -> srv-a ($A_IP, device A of U)"
[[ -n "$C_IP" && -n "$B_IP" ]] && png "$C" "$B_IP" "srv-c -> srv-b ($B_IP, device B of U)"
# ...and both U devices must reach srv-c:
[[ -n "$A_IP" && -n "$C_IP" ]] && png "$A" "$C_IP" "srv-a -> srv-c ($C_IP)"
[[ -n "$B_IP" && -n "$C_IP" ]] && png "$B" "$C_IP" "srv-b -> srv-c ($C_IP)"

# ---------------------------------------------------------------------------
step "8. data transfer — ray send / ray files accept"
# Returns 0 and prints nothing on success; verifies sha256 round-trips.
send_recv(){ # send_recv <from-ip> <to-ip> <to-hostname> <label>
  local from="$1" to="$2" peer="$3" label="$4"
  on "$from" "head -c 1048576 /dev/urandom > /tmp/e2e_src.bin; sha256sum /tmp/e2e_src.bin | cut -d' ' -f1 > /tmp/e2e_src.sha"
  local src_sha; src_sha="$(on "$from" 'cat /tmp/e2e_src.sha')"
  on "$from" "ray send /tmp/e2e_src.bin $peer" 2>&1 | strip | sed 's/^/      send| /'
  # poll the receiver for the incoming offer, then accept it
  local fid=""
  for _ in $(seq 1 12); do
    # Offer lines look like: "<id>  <from> (<mime>)  <filename>  <size>" — the
    # mime in parens distinguishes them from "No pending file transfers." etc.
    fid="$(on "$to" 'ray files' 2>/dev/null | strip | awk '/\(/ && NF>=4 {print $1; exit}')"
    [[ -n "$fid" ]] && break
    sleep 3
  done
  if [[ -z "$fid" ]]; then fail "$label: no incoming file offer on receiver"; return; fi
  on "$to" "rm -rf /tmp/e2e_recv && mkdir -p /tmp/e2e_recv && ray files accept $fid --output /tmp/e2e_recv" 2>&1 | strip | sed 's/^/      recv| /'
  local dst_sha=""
  for _ in $(seq 1 10); do
    dst_sha="$(on "$to" 'f=$(find /tmp/e2e_recv -type f | head -1); [ -n "$f" ] && sha256sum "$f" | cut -d" " -f1')"
    [[ -n "$dst_sha" ]] && break
    sleep 2
  done
  if [[ -n "$dst_sha" && "$dst_sha" == "$src_sha" ]]; then
    pass "$label (sha ${src_sha:0:12}… verified)"
  else
    fail "$label (sent ${src_sha:0:12}… got ${dst_sha:0:12}…)"
  fi
}
# C reaches BOTH physical devices backing identity U, addressed by hostname:
send_recv "$C" "$A" srv-a "ray send srv-c -> srv-a (device A of identity U)"
send_recv "$C" "$B" srv-b "ray send srv-c -> srv-b (device B of identity U)"
# reverse direction: a U device -> C
send_recv "$A" "$C" srv-c "ray send srv-a -> srv-c (reverse)"

# ---------------------------------------------------------------------------
step "summary"
if [[ "$FAILS" -eq 0 ]]; then
  printf '\033[32mALL CHECKS PASSED\033[0m\n'; exit 0
else
  printf '\033[31m%d CHECK(S) FAILED\033[0m\n' "$FAILS"; exit 1
fi
