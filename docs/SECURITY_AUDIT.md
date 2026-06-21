# pitopi Security & Correctness Audit

Date: 2026-06-21
Scope: full source tree (`src/*.rs`), focusing on the data plane (forwarding,
firewall, ACL), the control/membership plane (join, welcome, mesh hello, group
blob), the IPC/daemon boundary, and Magic DNS.

Findings are graded **Critical / High / Medium / Low / Info**. Items marked
**[FIXED]** are addressed in this pass; the rest are recommendations.

---

## Summary

The cryptographic core is sound: the per-network `SecretKey` signs the pkarr
record, the record carries the GroupBlob hash, and iroh-blobs content-addresses
the blob by that hash. That chain is not spoofable. The problems are in the
*layers above* the signed blob — peer-supplied fields that override or bypass
the signed state, and in the data-plane enforcement points that trust packet
fields they should not.

| Severity | Count | Fixed |
|----------|-------|-------|
| Critical | 2 | 0 (need design work) |
| High | 4 | 2 |
| Medium | 6 | 1 |
| Low / Info | 9 | 0 |

---

## Critical

### C1. Forged GroupBlob via `BlobUpdated` (unauthenticated hash)

`src/daemon.rs:2137` — `join_mesh_shared`'s control listener handles
`ControlMsg::BlobUpdated { hash }` by fetching blob `hash` from a peer and then
calling `verify_group_blob(&bytes, &hash)`. The "verification" only checks that
the fetched bytes match `hash` — which is trivially true because iroh-blobs
fetched *by* that hash. The hash itself comes from an **unauthenticated peer
message**, not from the signed pkarr record.

A malicious member can:

1. Craft a `GroupBlob` with arbitrary members (including itself as coordinator)
   and an ACL that permits its traffic.
2. Add it to its own blob store, compute `H = blake3(blob)`.
3. Send `BlobUpdated { hash: H }` to a victim.
4. The victim fetches the blob from the attacker, "verifies" it, and applies the
   forged members + ACL.

This fully defeats the coordinator's authority for any member that accepts the
`BlobUpdated` message.

**Fix:** `BlobUpdated` should not fetch-and-apply by the peer-claimed hash. It
should at most *trigger an early poll* of the signed pkarr record
(`spawn_group_poller` already resolves the authoritative hash every 60s and
fetches by it). Alternatively, only honor `BlobUpdated` when `hash` equals the
last hash seen from `dht::resolve_network`.

### C2. IP hijack via `MeshHello.ip` / `Welcome` member list

The IP carried in peer messages is trusted and used directly as the routing key:

- `src/daemon.rs:2175` (mesh acceptor): on `MeshHello`, `peers.add(ip, conn, …)`
  with `ip` taken from the message. `DashMap::insert` *overwrites* any existing
  entry for that IP.
- `src/daemon.rs:1840` (`join_mesh_shared`): the `Welcome { members }` list
  **replaces** the just-verified GroupBlob's member list (`MemberList::from_members(members)`).

A peer can claim any IP — including another member's IP — and steal routing for
it (victim's connection is orphaned in the `PeerTable`, all traffic to that IP
now goes to the attacker). The identity check (`peer_identity != transport_id`)
prevents identity spoofing but not IP spoofing.

**Root-cause fix:** never trust the `ip` field on the wire. Always recompute
`ip = derive_ip(identity)` and reject/ignore the carried value. The new
`membership::validate_member` / `validate_approved` helpers (added in this pass)
encode the invariant; they are now enforced at `decode_group_blob`
(`src/membership.rs:339`) so signed blobs cannot carry mismatched IPs. The
remaining work is to enforce the same at the `Welcome`/`MemberSync`/`MeshHello`
application sites in `daemon.rs` — which requires either ignoring the carried IP
or cross-checking against the GroupBlob.

---

## High

### H1. Inbound firewall bypass for non-IPv4 / truncated packets  **[FIXED]**

`src/forward.rs` `spawn_peer_reader`: previously, when `parse_packet_info`
returned `None` (IPv6, ARP, truncated, bad IHL), the packet **skipped the
firewall** and was written to the TUN. A peer could tunnel non-IPv4 to evade a
`default deny` inbound policy.

Fixed by extracting `evaluate_inbound()` which treats unparseable/oversized
packets as `DropMalformed`. Tests: `inbound_non_ipv4_dropped_as_malformed_not_bypassing_firewall`,
`inbound_oversized_datagram_dropped_as_malformed`, `inbound_firewall_denied_port`,
`inbound_acl_denied_before_firewall`, `inbound_clean_tcp_accepted`.

### H2. Unbounded incoming datagram size  **[FIXED]**

`spawn_peer_reader` did `datagram.to_vec()` with no size check. A peer could
send arbitrarily large QUIC datagrams to drive the node toward OOM. Now capped
at `MAX_PEER_DATAGRAM` (1500) inside `evaluate_inbound`.

### H3. `Welcome` member list overrides the verified GroupBlob

Even setting C2 aside, `join_mesh_shared` receives `Welcome { members }` from
the seed peer (which may be *any* member, not the coordinator) and stores those
members as the source of truth, discarding the GroupBlob's members that were
just fetched and hash-verified. A malicious seed peer can feed a tampered
member list to a joiner.

**Fix:** make the GroupBlob the authoritative member list; treat `Welcome` as a
hint only, or validate every `Welcome` member against the GroupBlob (or at least
against `validate_member`).

### H4. IPC socket world-writable on macOS (local privilege issue)

`src/daemon.rs:set_socket_group_permissions` does `chmod 0o666` on macOS so
"any user" can talk to the daemon. The daemon runs as **root** and owns the
TUN device. Any local unprivileged user can therefore issue `Shutdown`,
`Nuke`, `FirewallDefault deny`, `AclAllow`, `FirewallAdd` (pointed at any
peer), etc. This is local DoS / VPN tampering / traffic redirection.

On Linux it is `0660 root:pitopi` (better, but any `pitopi` group member has
full control).

**Fix:** on macOS do not chmod 0666. Either require group membership (create a
`pitopi` group like the Linux path) or restrict to root + a specific group.
Document the trust model explicitly.

---

## Medium

### M1. Stateful firewall is actually stateless — `default deny` breaks TCP  **[partial doc]**

`firewall::evaluate` matches only on `dst_port` with no connection tracking.
With `firewall default deny` inbound, return traffic for your own outbound
connections (coming back to your ephemeral source port) is dropped, so
`default deny` effectively breaks all outbound TCP too. There is no way to
express "allow established return traffic".

**Fix (design):** either document loudly that inbound `default deny` requires
explicit allow rules for every local listening port *and* breaks outbound TCP,
or implement minimal state tracking (track outgoing SYN → allow return
src_port). At minimum, match on `src_port` for inbound so users can allow
return traffic from a known remote port.

### M2. `resolve_short_id` prefix matching is ambiguous  **[doc]**

`daemon.rs:resolve_short_id` uses `identity.to_string().starts_with(short)`.
With many members, 4-hex-char prefixes collide and the first match wins
silently. An ACL/firewall rule can target the wrong peer. `self` is special
-cased, which is good.

**Fix:** require the prefix to be unambiguous; error (or warn) on collision.
Consider requiring the full `EndpointId`, or a longer prefix, for
security-relevant commands.

### M3. `acl_allow` CLI silently turns typos into tag rules

`acl.rs:parse_target` / `daemon.rs:acl_allow`: anything that isn't `all` and
isn't a resolvable peer ID becomes a `Target::Tag`. So `acl allow srvrs -> all`
(typo of `servers`) silently creates a tag rule matching no one, and the user
believes traffic is allowed. Combined with the deny-by-default-when-rules-exist
model, this can quietly black-hole traffic.

**Fix:** require tag names to be declared with `tag` first, or require a
sigil (e.g. `tag:servers`) for tag targets in `allow`. At least warn if a
non-resolvable, undeclared tag is used as a target.

### M4. `derive_ip` reserved-address remap introduces guaranteed collisions  **[doc]**

`membership.rs:derive_ip`:

```rust
let host_bits = hash & 0x003F_FFFF;
let host_bits = if host_bits <= 1 { host_bits + 2 } else { host_bits };
```

An identity hashing to `0` maps to host `2` — colliding with an identity
hashing to `2`. Likewise `1`↔`3`. So 4 specific hash values produce 2
guaranteed collisions (vs. the documented "extremely rare" collisions). Low
practical impact (22-bit space, ~4M addresses) but it is a latent correctness
bug. A clean fix is to re-hash when `host_bits <= 1` rather than add 2.

### M5. `nuke` does not evict existing members

`daemon.rs:nuke_network` publishes an empty record (empty blob hash, no seeds)
and leaves. Existing members' pollers see the new hash, fail to fetch the empty
blob (coordinator gone), and keep their old state and live mesh links. So
"nuke" only blocks *new* joins; the network keeps running without the
coordinator. The name oversells the effect.

**Fix:** either rename/document accurately, or have the coordinator broadcast a
teardown control message and have peers drop the network on receipt.

### M6. Audit log is not wired in

`src/audit.rs` exists ("not yet wired in" per CLAUDE.md) and is never
constructed. For a security product, joins/approvals/ACL changes/firewall
changes/packet denials should be auditable. The `AuditLog` API also only covers
connect/disconnect — it should cover policy mutations.

---

## Low / Info

### L1. Outbound `run_mesh` does not validate `src_ip`

`forward.rs:run_mesh` routes on `dst_ip` only. A locally-originated packet with
a spoofed source IP (another peer's IP, or an out-of-range src) is forwarded.
Requires raw sockets / `CAP_NET_RAW` locally, so impact is limited, but a
spoofed src could let a local process impersonate another peer to ACL logic on
remote peers (ACL is evaluated src→dst). Consider dropping packets whose
`src_ip != local_ip` for the relevant network.

### L2. `parse_packet_info` does not validate `ihl >= 5`

`firewall.rs`: `ihl` is read from the packet and used as `header_len = ihl*4`
without checking `ihl >= 5` (minimum legal IPv4 header). For `ihl < 5` the
"transport" port bytes are read from the IP header region, producing nonsense
ports. Not a security hole (ports just mis-match), but worth a guard.

### L3. `check_cgnat_conflict` silently no-ops on Linux without `ifconfig`

`tun.rs`: uses `ifconfig`, which is absent on many modern Linux systems (uses
`ip`). On failure it returns `Ok(())`, so the CGNAT-conflict check (e.g. with
Tailscale) is silently skipped. Use `ip -o addr` on Linux.

### L4. `restore_coordinator_network` drops the coordinator's hostname

On restore, self is re-added with `hostname: None` even if one was previously
configured and is still in the member list. Magic DNS for the coordinator
breaks across restarts.

### L5. Hostname collisions not resolved on join

`join_network_inner` generates a random hostname without checking the existing
hostname table; two peers can pick the same noun, making DNS ambiguous.
`hostname::resolve_collision` exists but is unused (clippy dead-code warning).

### L6. `spawn_group_poller` does not persist learned state

When the poller applies a new GroupBlob, it updates in-memory `members`/`acl`
but neither writes the `.acl` file nor updates `networks.toml`. On restart,
stale state is loaded (coordinator restore path). Membership/ACL changes
learned via polling are lost across restarts.

### L7. DashMap `.unwrap()` panics after network removal

Several ACL handlers in `daemon.rs` (e.g. `acl_tag`) do
`self.networks.get(network).unwrap()` after releasing the write lock. A
concurrent `leave_network` between the two calls panics the root daemon. Handle
`None`.

### L8. `MemberList::from_members` silently drops colliding members

`let _ = list.add(m);` swallows `IpCollision` errors. A blob with a duplicate
IP silently shrinks the member list. Should at least log.

### L9. Control message size limits

`control.rs:recv_msg` caps at 65536 bytes; `ipc.rs:recv_msg` caps at 1 MiB.
Both are reasonable. `Welcome`/`MemberSync` carry the full member list, so a
coordinator can push ~800 members per message — bounded, fine.

---

## What was fixed in this pass

1. **H1 + H2** — `src/forward.rs`: extracted testable `evaluate_inbound()` that
   drops oversized (>1500B) and non-IPv4/unparseable packets, and applies ACL →
   firewall in order. `spawn_peer_reader` now uses it. (5 new tests.)
2. **C2 (partial)** — `src/membership.rs`: added `validate_member` /
   `validate_approved` / `ensure_in_cgnat_range` and enforce them in
   `decode_group_blob`, so signed GroupBlobs can no longer carry a member whose
   IP doesn't match its identity or is reserved. (8 new tests.)
3. **Hostname validation** — `src/daemon.rs`: `--hostname` is now validated with
   `is_valid_hostname` in both `create` and `join`, rejecting invalid DNS labels
   before they enter the hostname table.

Tests: 118 passing (was 105), `cargo clippy` clean apart from pre-existing
dead-code warnings (`resolve_collision`, `audit`).

---

## Recommended next steps (priority order)

1. **C1** — Stop applying `BlobUpdated` by peer-claimed hash; trigger a signed
   pkarr poll instead.
2. **C2 / H3** — Stop trusting the `ip` field in `Welcome`/`MemberSync`/
   `MeshHello`; derive from identity, or validate against the GroupBlob.
3. **H4** — Fix macOS IPC socket permissions.
4. **M1** — Decide firewall statefulness; at minimum document the
   `default deny` foot-gun.
5. **M2 / M3** — Make peer-ID resolution and ACL tag resolution fail loud, not
   silent.
6. **M6** — Wire in the audit log for policy mutations and join/approve events.
7. **L7** — Harden daemon handlers against concurrent network removal.
