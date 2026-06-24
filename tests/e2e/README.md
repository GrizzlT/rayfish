# Rayfish end-to-end tests

Each scenario provisions real Scaleway instances, deploys `ray` over SSH, drives a
flow end to end, and prints a `PASS`/`FAIL` line per check (exit non-zero on any
failure). The shared SSH/deploy/reset/assert plumbing lives in
[`../lib/`](../lib) and is sourced by every scenario.

## Scenarios

| Dir | Hosts | What it proves |
|-----|-------|----------------|
| [`device-cert/`](device-cert) | 3 | A third peer reaches a user identity backed by two paired devices (`ray pair` + DeviceCert), over a closed (invite-gated) network. |
| [`connect/`](connect) | 2 | The `ray connect` direct 2-peer friend-request flow over the public pkarr DHT — request, approve, `[direct]` network, ping + `ray send`, per-network firewall, offline negative case. |

Each scenario is self-contained:

```bash
tests/e2e/<scenario>/provision.sh   # spin up instances -> <scenario>/.servers
tests/e2e/<scenario>/run.sh         # deploy + drive the flow + assert
tests/e2e/<scenario>/teardown.sh    # destroy the instances (manual)
```

The throughput/latency benchmark is a sibling suite under
[`../bench/`](../bench) (same shared `tests/lib/`).

## Prerequisites (all scenarios)

- `scw` authenticated (`scw account project list` should work) and `jq` installed.
- Docker running (used by `cross` for the x86_64-linux build behind `just deploy`),
  plus `just`.
- Your `~/.ssh/id_ed25519` public key registered in the Scaleway account so the
  instances accept `root@<ip>`. Override the key with `SSH_KEY=…`.

## Common environment overrides

| Var | Default | Meaning |
|-----|---------|---------|
| `ZONE` | `fr-par-1` | Scaleway zone (provision) |
| `TYPE` | `DEV1-S` | instance type (provision) |
| `IMAGE` | `ubuntu_jammy` | instance image label (provision) |
| `SSH_KEY` | `~/.ssh/id_ed25519` | private key for `root@<ip>` |
| `KEEP_STATE` | `0` | `1` skips the per-run rayfish state wipe |
