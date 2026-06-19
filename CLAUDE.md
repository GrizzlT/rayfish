# Pitopi

P2P mesh VPN powered by [iroh](https://iroh.computer). Connects peers by cryptographic identity (EndpointId), not IP address. Users create and join virtual networks with assigned IPs in the 100.64.0.0/10 (CGNAT) range.

## Build & Run

```bash
cargo -q build
cargo -q check
cargo -q test
cargo -q clippy
```

### Running

```bash
# Create a network (coordinator)
sudo cargo -q run -- create --name gaming

# Join using room code or raw endpoint ID
sudo cargo -q run -- join <room-code-or-endpoint-id> --name gaming

# Manage networks
cargo -q run -- list                # show saved networks
cargo -q run -- leave gaming        # remove from config
cargo -q run -- status              # show active connections

# Connect/disconnect all saved networks
sudo cargo -q run -- up
cargo -q run -- down

# System service
sudo cargo -q run -- install-service
sudo cargo -q run -- uninstall-service

# Shell completions
cargo -q run -- completions bash > /etc/bash_completion.d/pitopi
```

Requires `sudo` for commands that create TUN devices (`create`, `join`, `up`).

### Cross-compile & deploy

```bash
just cross                   # build for x86_64 Linux
just deploy <ip>             # cross-build + rsync + install to server
```

## Architecture

```
App (Minecraft, etc.) → TUN device (100.64.x.x) → pitopi → iroh QUIC datagrams → peer
```

### Modules

- `src/main.rs` — CLI (clap), coordinator/joiner orchestration, peer handshake
- `src/identity.rs` — persistent Ed25519 keypair at `~/.config/pitopi/secret_key`
- `src/transport.rs` — iroh endpoint setup, per-network ALPN, connect/accept
- `src/tun.rs` — TUN device creation with per-subnet virtual IPs, async packet I/O
- `src/forward.rs` — multi-peer forwarding: TUN → routing table → correct peer connection
- `src/control.rs` — control protocol: Welcome, PeerJoined, PeerLeft, MeshHello, MeshWelcome, AdvertiseServices
- `src/peers.rs` — PeerTable (routing by dest IP) and IpAllocator (sequential assignment per subnet)
- `src/config.rs` — persistent network config at `~/.config/pitopi/networks.toml`
- `src/room_code.rs` — z-base-32 room codes with dashes for human-friendly sharing
- `src/acl.rs` — ACL policy engine: default policies, per-rule src/dst/port matching, packet filtering
- `src/audit.rs` — append-only audit log at `~/.config/pitopi/audit.log`
- `src/stats.rs` — packet/byte counters with periodic logging
- `src/shutdown.rs` — SIGINT/SIGTERM handling via CancellationToken

### Key flows

**Create (coordinator):** creates endpoint → listens for connections → on new peer: assigns IP via IpAllocator, sends Welcome with peer list, broadcasts PeerJoined to existing peers, spawns datagram reader.

**Join:** connects to coordinator → receives Welcome (assigned IP + peer list) → creates TUN device → connects to each existing peer with MeshHello → spawns per-peer datagram readers → runs mesh forwarding loop.

**Mesh forwarding:** TUN read loop extracts dest IP from IPv4 header bytes 16-19, looks up PeerTable, sends datagram on correct connection. Per-peer reader tasks write incoming datagrams to a shared TUN writer channel.

**Network isolation:** each network gets its own ALPN (`pitopi/net/<name>`), TUN device, and /24 subnet. A single shared iroh Endpoint accepts connections for all networks, filtering by ALPN on accept.

## Key Dependencies

- `iroh` — P2P QUIC transport with NAT traversal and relay fallback
- `tun` — cross-platform TUN device (macOS utun, Linux /dev/net/tun)
- `tokio` — async runtime
- `clap` + `clap_complete` — CLI parsing and shell completions
- `serde` + `serde_json` + `toml` — serialization for control messages and config
- `dirs` — platform config directory resolution

## Conventions

- Use `cargo -q` for all cargo commands
- Use `tracing` for logging (INFO level by default, no env filter)
- ALPN per network: `pitopi/net/<name>` (e.g., `pitopi/net/gaming`)
- Virtual IPs: 100.64.{subnet}.0/24 range — subnet index per network
- TUN MTU: 1200 (fits within QUIC datagram limits)
- Identity persists to `~/.config/pitopi/secret_key` — same EndpointId across restarts
- Config persists to `~/.config/pitopi/networks.toml`
- macOS TUN requires destination address (point-to-point interface)
- Control messages: length-prefixed JSON (4-byte BE length + JSON body) over QUIC bidirectional streams
- Room codes: z-base-32 with dashes every 4 chars, parsed via `room_code::parse_node_id()`
