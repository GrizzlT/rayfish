# Pitopi

A peer-to-peer mesh VPN that lets you create private virtual networks without any infrastructure. Built on [iroh](https://iroh.computer), it connects peers by cryptographic identity — not IP addresses — so you never need to deal with port forwarding, dynamic DNS, or firewall rules.

## Why?

You want to play Minecraft with friends, but nobody wants to set up port forwarding or pay for a hosted server. With Pitopi, one person creates a network, shares a short code, and everyone joins. Each player gets a virtual IP and the game thinks you're all on the same LAN.

But it's not just for games. Pitopi gives you a private, encrypted network between any set of devices — work machines, home servers, cloud instances — without trusting a third party.

## How it works

1. **Create a network** — one peer starts a network and becomes the coordinator
2. **Share the code** — the creator gets a short room code (like `ybnj-raqe-...`) to share with friends
3. **Join** — peers connect using the room code. iroh handles NAT traversal, hole-punching, and encrypted transport automatically
4. **Full mesh** — the coordinator assigns virtual IPs and broadcasts the peer list. Every peer connects directly to every other peer
5. **Use it** — every peer gets a virtual IP (100.64.x.x). Any app that uses TCP/UDP just works

Under the hood, Pitopi creates a TUN device on each machine, captures IP packets, and tunnels them through iroh's QUIC-based P2P connections. If direct connections aren't possible (~10% of cases), traffic falls back to encrypted relay servers.

## Quick start

```bash
# Build
cargo build

# Create a network (on machine A)
sudo pitopi create --name gaming
# > Network "gaming" created
# > Your IP: 100.64.0.1
# > Room code: ybnj-raqe-c5s6-...
# > Share this code with peers to join

# Join the network (on machine B)
sudo pitopi join ybnj-raqe-c5s6-... --name gaming
# > Joined network "gaming"
# > Your IP: 100.64.0.2
# > Connected to 1 peer(s)

# Now you can reach each other
ping 100.64.0.1   # from machine B
ping 100.64.0.2   # from machine A
```

Requires `sudo` because TUN devices need elevated privileges.

## Commands

```
pitopi create [--name <name>]       Create a new network (you become the coordinator)
pitopi join <code> [--name <name>]  Join a network using a room code or endpoint ID
pitopi list                         List saved networks
pitopi leave <name>                 Remove a network from saved config
pitopi status                       Show active networks, peers, and connection quality
pitopi up                           Connect to all saved networks
pitopi down                         Disconnect from all networks
pitopi install-service              Install systemd (Linux) or launchd (macOS) service
pitopi uninstall-service            Remove the system service
pitopi completions <shell>          Generate shell completions (bash, zsh, fish)
```

## Multiple networks

You can run multiple isolated networks simultaneously. Each gets its own TUN device and /24 subnet:

```bash
sudo pitopi create --name gaming    # 100.64.0.0/24
sudo pitopi create --name work      # 100.64.1.0/24
```

Networks are fully isolated — different ALPN protocols, different TUN devices, no cross-talk.

## Running as a service

```bash
sudo pitopi install-service    # installs systemd unit or launchd plist
sudo pitopi up                 # connects to all saved networks
```

The service runs `pitopi up` on boot, reconnecting to all saved networks automatically.

## Configuration

Network memberships are stored at `~/.config/pitopi/networks.toml`. Identity (Ed25519 keypair) persists at `~/.config/pitopi/secret_key` — same endpoint ID across restarts.

## Building

```bash
cargo build
```

Requires Rust 2024 edition. Cross-compile for Linux servers:

```bash
just cross                   # build for x86_64 Linux
just deploy <ip>             # cross-build + rsync + install to server
```

## Architecture

```
App (Minecraft, etc.) → TUN device (100.64.x.x) → pitopi → iroh QUIC datagrams → peer
```

- Full mesh topology — every peer connects directly to every other peer
- Coordinator assigns IPs and broadcasts peer list via a control channel (QUIC bidirectional stream)
- Data flows as QUIC datagrams (low-latency, no head-of-line blocking)
- Routing table dispatches packets by destination IP from the IPv4 header
- ACL policy engine filters packets at the forwarding layer
- Per-network ALPN isolation on a single shared iroh endpoint

## Roadmap

See [TODO.md](TODO.md) for the full roadmap. Current status:

- [x] Point-to-point tunnel between two peers
- [x] Multi-peer full mesh (N peers in one network)
- [x] Multiple simultaneous networks with isolation
- [x] Persistent network config
- [x] Room codes for easy sharing
- [x] ACL policy engine and audit logging
- [x] Systemd/launchd service integration
- [ ] Daemon architecture (pitopid + thin CLI client)
- [ ] Social discovery (Discord, Slack, Steam)
- [ ] macOS Network Extension (no sudo)
- [ ] Windows, iOS, Android
