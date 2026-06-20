# The Pitopi Book

A complete guide to pitopi's architecture, protocols, and internals.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Identity](#3-identity)
4. [Membership](#4-membership)
5. [Transport](#5-transport)
6. [Control Protocol](#6-control-protocol)
7. [TUN Device](#7-tun-device)
8. [Packet Forwarding](#8-packet-forwarding)
9. [Peer Table](#9-peer-table)
10. [Configuration](#10-configuration)
11. [Three-Word Names](#11-three-word-names)
12. [Access Control](#12-access-control)
13. [Audit Logging](#13-audit-logging)
14. [Statistics](#14-statistics)
15. [Shutdown](#15-shutdown)
16. [DHT Membership](#16-dht-membership)
17. [Network Lifecycle](#17-network-lifecycle)
18. [Daemon Architecture](#18-daemon-architecture)
19. [Code Flow Diagrams](#19-code-flow-diagrams)
20. [Security Model](#20-security-model)

---

## 1. Introduction

Pitopi is a peer-to-peer mesh VPN that creates private virtual networks without any centralized infrastructure. It is built on top of [iroh](https://iroh.computer), a library that provides encrypted QUIC-based peer-to-peer connectivity with automatic NAT traversal, hole-punching, and relay fallback.

The core idea is simple: every peer gets a virtual IP address derived from their cryptographic identity. When an application on your machine sends a packet to that virtual IP, pitopi captures it through a TUN device, looks up which peer owns that IP, and tunnels the packet over an encrypted QUIC connection to the right machine. To the application, it looks like all peers are on the same local network.

### The data path

```
Application (e.g., Minecraft)
    |
    v
TUN device (100.64.x.x)
    |
    v
pitopi forwarding loop
    |  reads IPv4 packets from TUN
    |  extracts destination IP from header bytes 16-19
    |  looks up the peer connection in the routing table
    v
iroh QUIC datagram
    |  encrypted, NAT-traversed
    v
Remote peer's pitopi
    |  receives datagram
    |  writes packet to local TUN device
    v
Remote application
```

Pitopi uses QUIC datagrams (not streams) for data packets. Datagrams are unreliable and unordered -- just like UDP -- which means low latency and no head-of-line blocking. This makes pitopi well-suited for real-time applications like games.

### Address space

All peers live in the `100.64.0.0/10` range, which is the IANA-assigned Carrier-Grade NAT (CGNAT) block. This range is reserved for internal use by ISPs and is extremely unlikely to collide with any real network your machine participates in. The /10 prefix gives 22 bits of host address space, allowing roughly 4 million unique addresses.

### Why not WireGuard?

WireGuard is excellent for static, pre-configured tunnels between known endpoints. Pitopi solves a different problem: you don't know your peers' IP addresses, you don't want to configure port forwarding, and you want peers to find each other by cryptographic identity alone. iroh handles the hard part -- discovering peers through relay servers, punching through NATs, and falling back to relayed connections when direct paths aren't possible.

### Network topology

A user can be part of multiple networks simultaneously. Each network is an independent full mesh -- every peer connects directly to every other peer. Networks are completely isolated from each other (different ALPNs, different member lists).

Your device sits at the center of all your networks. Each network is a full-mesh bubble, and you participate in all of them simultaneously:

```
  .-------------------------------------. .-------------------------------------.
  |        My gaming network :)          | |         My work network :(          |
  |                                      | |                                     |
  |          (Friend 1)                  | |           (Co-worker 1)             |
  |           /  |  \                    | |             /   |   \               |
  |          /   |   \                   | |            /    |    \              |
  |         /    |    \                  | |           /     |     \             |
  | (Minecraft)  |  (Your)--------------+-+---(Your)--    (Company)             |
  |  (server)----|  (device)             | |   (device)\    |    (server 1)     |
  |         \    |    /                  | |            \   |     /              |
  |          \   |   /                   | |             \  |    /               |
  |           \  |  /                    | |           (Co-worker 2)             |
  |          (Friend 2)                  | |                |                    |
  |                                      | |             (Company)              |
  |  every peer <---> every peer         | |             (server 2)             |
  '--------------------------------------' '-------------------------------------'
```

One pitopi process, one TUN device, one routing table -- shared across all your networks.

### Enterprise use case

In a company, different departments run separate networks. Shared services (like Jenkins) join multiple networks, sitting at the overlap:

```
  .-------------------------------. .-------------------------------.
  |         Accounting            | |          Technology            |
  |                               | |                               |
  | (server) (server) (server)    | |    (server) (server) (server) |
  |                               | |                               |
  | (User 1) (User 2) (User 3)   | |   (User 1) (User 2) (User 3) |
  |                       .-------+-+-------.                       |
  |                       |    (Jenkins)    |                       |
  '-----------------------|                 |-----------------------'
                          '-------+-+-------'
                     .------------+-+----------------------------.
                     |          Webpage                          |
                     |                                           |
                     |  (server) (server) (server)               |
                     |                                           |
                     |  (User 1) (User 2) (User 3)              |
                     '-------------------------------------------'

  Jenkins is a member of ALL THREE networks.
  It can reach accounting servers, tech servers, and web servers.
  But User 1 in "accounting" CANNOT reach servers in "technology" --
  networks are isolated unless a device explicitly joins both.
```

### Joining a network (invitation)

The coordinator creates a network and gets a three-word name. That name is the invitation:

```
                                         .-------------------------.
                                         |    User's network       |
  (Friend 1) <--- invitation ---------- |                         |
                   (three-word name)     |     (User's device)     |
                                         |                         |
                                         '-------------------------'

  1.  User creates network:    pitopi create
      --> prints network name: gentle-amber-fox
          (adjective-noun-noun, randomly generated)

  2.  User shares name with Friend 1 (chat, email, etc.)

  3.  Friend 1 joins:          pitopi join gentle-amber-fox
      --> daemon resolves name via directory DHT
      --> fetches member list from online peers via iroh-blobs
      --> coordinator approves (or peer welcomes if already approved)
      --> Friend 1 gets Welcome (member list, approved list)
      --> Friend 1 connects to all existing peers
      --> full mesh established
```

### Per-node architecture

Inside each peer, the stack looks like this:

```
┌─────────────────────────────────────────────────┐
│                  Applications                    │
│            (Minecraft, SSH, curl, ...)            │
└──────────────────────┬──────────────────────────┘
                       │ regular TCP/UDP to 100.64.x.x
                       ▼
┌─────────────────────────────────────────────────┐
│               TUN device (kernel)                │
│         100.64.0.0/10 — captures all traffic     │
│         to the virtual network range             │
└──────┬──────────────────────────────┬────────────┘
       │ read                         │ write
       ▼                              ▼
┌─────────────┐               ┌─────────────┐
│  TunReader  │               │  TunWriter  │
│  (run_mesh) │               │  (tun_rx)   │
└──────┬──────┘               └──────▲──────┘
       │                              │
       │ dest_ip → PeerTable          │ tun_tx channel
       │ lookup → Connection          │
       ▼                              │
┌─────────────────────┐    ┌──────────┴──────────┐
│    PeerTable        │    │  spawn_peer_reader   │
│  ┌───────────────┐  │    │  (one per peer)      │
│  │100.64.23.5    │──┼──▶ │                      │
│  │  → conn to A  │  │    │  conn.read_datagram()│
│  │100.64.87.12   │  │    │    → tun_tx.send()   │
│  │  → conn to B  │  │    └─────────────────────┘
│  │100.64.42.200  │  │
│  │  → conn to C  │  │
│  └───────────────┘  │
└──────────┬──────────┘
           │ conn.send_datagram()
           ▼
┌─────────────────────────────────────────────────┐
│              iroh QUIC endpoint                  │
│    NAT traversal, hole-punching, relay fallback  │
│    TLS 1.3 + Ed25519 identity authentication     │
└──────────────────────┬──────────────────────────┘
                       │ encrypted UDP
                       ▼
                   Internet
```

---

## 2. Getting Started

### Building

```bash
cargo build
```

Requires Rust 2024 edition.

### Starting the daemon

Before using any network commands, start the daemon:

```bash
sudo pitopi daemon
```

The daemon is a long-lived process that owns the iroh endpoint, TUN device, and all peer connections. It listens for commands on a Unix socket at `/var/run/pitopi/pitopi.sock`. On startup, it restores all previously saved networks from config.

`pitopi up` is an alias for `pitopi daemon`.

### Creating a network

In another terminal, create a network:

```bash
pitopi create
```

This produces output like:

```
Network 'gentle-amber-fox' created.
  IP: 100.64.23.142
```

The daemon automatically generates a three-word name (adjective-noun-noun) and publishes the network to the DHT. The coordinator's IP is deterministically derived from their cryptographic identity.

### Joining a network

Other peers join by providing the three-word name:

```bash
pitopi join gentle-amber-fox
```

The daemon resolves the name via the directory DHT, fetches the current member list from online peers, connects to the coordinator (or any peer), receives approval and a member list, and establishes direct connections to every other peer in the mesh.

### Nuking a network

To permanently remove a network and announce its removal to all peers:

```bash
pitopi nuke gentle-amber-fox
```

This publishes empty membership and seed list records to the DHT (so new joiners know the network no longer exists), then leaves the network. Use `--force` to skip the confirmation prompt.

### Checking status

Once you have networks running, query the daemon for live state:

```bash
pitopi status
# > Endpoint: <your-endpoint-id>
# >   gaming [coordinator]
# >     IP: 100.64.23.142
# >     Peers:
# >       100.64.7.201 (<peer-endpoint-id>)
```

### Leaving a network

```bash
pitopi leave gaming
```

This tears down all connections for that network, removes peers from the routing table, and deletes it from the saved config.

### Shutting down

```bash
pitopi down    # signals the daemon to shut down gracefully
```

### Socket permissions

The daemon runs as root and creates the IPC socket at `/var/run/pitopi/pitopi.sock`. By default, only root can connect. To allow unprivileged users to run commands, create a `pitopi` group and add users to it:

```bash
sudo groupadd pitopi
sudo usermod -aG pitopi $USER
# log out and back in, or: newgrp pitopi
```

The daemon automatically sets the socket to `root:pitopi` with mode `0660` if the group exists.

### Why sudo?

TUN devices are virtual network interfaces. Creating them requires root privileges on both Linux and macOS. Only `pitopi daemon` (and its alias `pitopi up`) requires root. All other commands are thin IPC clients that talk to the daemon and run unprivileged.

### All commands

| Command | Description | Needs daemon |
|---------|-------------|:---:|
| `sudo pitopi daemon` | Start the daemon (owns TUN + endpoint) | — |
| `sudo pitopi up` | Alias for `daemon` | — |
| `pitopi create` | Create a network (generates three-word name) | Yes |
| `pitopi join NAME` | Join a network by three-word name via DHT lookup | Yes |
| `pitopi leave NAME` | Leave a network and remove config | Yes |
| `pitopi nuke NAME [--force]` | Publish empty records to DHT then leave | Yes |
| `pitopi status` | Show active networks, peers, and IPs | Yes |
| `pitopi down` | Shut down the daemon | Yes |
| `pitopi list` | Show networks (queries daemon if running) | No |
| `pitopi acl NAME tag TAG PEERS…` | Assign a tag to one or more peers | Yes |
| `pitopi acl NAME untag TAG PEERS…` | Remove a tag from peers | Yes |
| `pitopi acl NAME allow SRC DST` | Add an allow rule | Yes |
| `pitopi acl NAME remove INDEX` | Remove a rule by index | Yes |
| `pitopi acl NAME show` | Display current ACL state | Yes |
| `pitopi acl NAME apply` | Re-publish current ACL to all peers | Yes |
| `pitopi install-service` | Install systemd/launchd service | No |
| `pitopi uninstall-service` | Remove system service | No |
| `pitopi completions SHELL` | Generate shell completions | No |

### Deploying to servers

```bash
just deploy <ip>    # cross-build + install + create pitopi group + start daemon service
```

This handles everything: builds for x86_64 Linux, installs the binary, creates the `pitopi` group, installs a systemd service, and starts the daemon. On subsequent deploys it restarts the service to pick up the new binary.

---

## 3. Identity

**Module:** `src/identity.rs`

Every pitopi node has a persistent Ed25519 keypair stored at `~/.config/pitopi/secret_key`. This keypair is the node's cryptographic identity -- it determines the node's EndpointId and, by extension, its virtual IP address.

### Key generation and persistence

The first time pitopi runs, it generates a random Ed25519 secret key and writes the raw 32 bytes to disk:

```
~/.config/pitopi/secret_key  (32 bytes, binary)
```

On subsequent runs, it loads the existing key. This means a node always has the same EndpointId and the same virtual IP across restarts, reboots, and even machine migrations (as long as you copy the key file).

### EndpointId

The public half of the Ed25519 keypair is the node's `EndpointId`. This is what iroh uses to identify and route to the node. It's a 32-byte value that can be displayed as a hex string or encoded as a z-base-32 room code.

The EndpointId serves dual purpose:

1. **Network address:** iroh uses it to locate and connect to the peer, handling NAT traversal and relay automatically.
2. **Identity root:** the virtual IP is deterministically derived from it, and all membership records reference it as the peer's identity string.

### Security properties

The secret key never leaves the machine. All authentication happens at the QUIC transport layer -- when two peers connect, iroh performs a mutual TLS handshake using their Ed25519 keys. A peer's EndpointId is the public key from this handshake, so a peer cannot impersonate another peer's identity at the transport level.

---

## 4. Membership

**Module:** `src/membership.rs`

The membership module is the heart of pitopi's identity and authorization system. It defines how peers are identified, how their IP addresses are assigned, and who is allowed to join a network.

### Identity-derived IP addresses

Rather than assigning IPs sequentially (first joiner gets .2, second gets .3), pitopi derives each peer's IP deterministically from their identity string using FNV-1a hashing:

```
identity string  ->  FNV-1a hash  ->  lower 22 bits  ->  100.64.0.0/10 address
```

The FNV-1a algorithm was chosen for its simplicity (no external dependencies), good distribution, and determinism. The 22-bit host space maps directly to the /10 CGNAT range.

Two host addresses are reserved:
- `100.64.0.0` -- network address (host bits = 0)
- `100.64.0.1` -- TUN gateway address (host bits = 1)

If the hash lands on either of these, the address is shifted to host bits 2 or 3.

The key property: **a peer always gets the same IP, in every network, on every run.** This makes the address a stable identifier that other peers and applications can rely on.

#### Collision handling

With 22 bits of address space and a hash function, collisions are possible. The birthday problem gives roughly a 50% collision probability around 2,000 peers. For pitopi's target use case (small groups of friends or coworkers), this is extremely unlikely, but the system handles it gracefully at two levels:

1. **Coordinator-side check:** Before broadcasting a `MemberApproved` message, the coordinator checks the derived IP against both the member list and the approved list. If a collision is found with a different identity, the peer receives a `JoinDenied` with the reason "IP collision" and the approval is never broadcast.

2. **Joiner-side check:** When a peer receives a `Welcome` message containing the member list, it checks its own derived IP against all existing members. If a collision is detected, the joiner bails out with an error rather than entering the mesh. This serves as a defense-in-depth check and is the primary collision guard when the joiner connects via a non-coordinator peer.

The `MemberList::add()` method enforces collision detection at the data structure level: it rejects any addition where a *different* identity already occupies the same IP. Re-adding the same identity with the same IP is allowed (idempotent update).

### The IdentityProvider trait

All identity operations are abstracted behind a trait to allow swapping the identity backend:

```rust
pub trait IdentityProvider: Send + Sync {
    fn local_ip(&self) -> Ipv4Addr;
    fn local_identity(&self) -> EndpointId;
    fn derive_ip(&self, peer_identity: &EndpointId) -> Ipv4Addr;
}
```

The current implementation, `IrohIdentityProvider`, wraps an iroh `EndpointId`:

- `local_ip()` returns the FNV-1a-derived IP for this node's EndpointId.
- `local_identity()` returns the EndpointId (iroh `PublicKey`).
- `derive_ip(peer)` converts the EndpointId to a string internally and hashes it to an IP.

Identity verification happens at the transport level — the QUIC handshake already authenticates the EndpointId, so `conn.remote_id()` is trusted without additional application-level checks.

### MemberList

The `MemberList` is an in-memory registry of all members in a network:

```rust
pub struct Member {
    pub identity: EndpointId,   // iroh public key
    pub ip: Ipv4Addr,           // derived from identity
    pub is_coordinator: bool,   // whether this member created the network
}
```

The list is stored as a `HashMap<EndpointId, Member>` keyed by identity. It supports:

- `add(member)` -- insert with IP collision detection
- `remove(identity)` -- remove a member
- `get(identity)` -- lookup by identity string
- `get_by_ip(ip)` -- lookup by virtual IP
- `is_member(identity)` -- membership check
- `all()` -- list all members

### ApprovedList

The `ApprovedList` tracks peers that have been approved by the coordinator but haven't connected to the mesh yet. This is the key data structure behind the "coordinator as gatekeeper" model -- it decouples authorization from welcome.

```rust
pub struct ApprovedEntry {
    pub identity: EndpointId,   // iroh public key
    pub ip: Ipv4Addr,           // derived from identity
}
```

The list is stored as a `HashMap<EndpointId, ApprovedEntry>` keyed by identity. It supports:

- `approve(entry, &MemberList)` -- add with collision check against both the member list and existing approved entries
- `is_approved(identity)` -- check if a peer is pre-approved
- `remove(identity)` -- remove an entry (used when promoting to full member)
- `all()` -- list all approved entries
- `from_entries(entries)` -- bulk load from a vector

The approve-then-promote lifecycle:

1. Coordinator approves a peer → entry added to `ApprovedList`
2. Coordinator broadcasts `MemberApproved` → all peers add the entry to their local approved lists
3. Approved peer connects to any peer → welcoming peer removes from `ApprovedList`, adds to `MemberList`
4. Welcoming peer broadcasts `MemberSync` → all peers update their member lists

### MembershipData and canonical serialization

`MembershipData` is the canonical, serializable form of network membership state. It is serialized to msgpack (sorted by identity for determinism) and stored in the iroh-blobs store. It is also blake3-hashed to produce the hash published to the membership DHT record.

```rust
pub struct MembershipData {
    pub members: Vec<MemberEntry>,
    pub approved: Vec<ApprovedConfigEntry>,
    pub network_secret: [u8; 32],           // for seed list record signing
    pub membership_signing_key: [u8; 32],   // coordinator's per-network DHT signing key
}
```

Including `network_secret` and `membership_signing_key` in the blob means every peer that receives the membership data can independently publish seed list records and verify DHT keys — not just the coordinator. `canonical_membership_bytes_with_secrets()` produces the canonical msgpack bytes for hashing and storage.

### NetworkState

The `MemberList` and `ApprovedList` are bundled into a `NetworkState` struct and shared across async tasks using `Arc<std::sync::RwLock<NetworkState>>`:

```rust
struct NetworkState {
    members: MemberList,
    approved: ApprovedList,
}
```

The standard library `RwLock` (not tokio's) is used because all operations are fast, non-blocking, and never hold the lock across an `.await` point.

### Group modes

Networks can operate in one of two membership modes:

**Restricted (default):** Only the coordinator can authorize new members. However, any peer can *welcome* an already-approved member. This means the coordinator doesn't need to be online when the approved peer actually connects -- it just needs to have broadcast the approval beforehand.

**Open:** Any member can both authorize and welcome new joiners. When a connection comes in, any peer that receives it checks the `MembershipPolicy` and, if they're authorized (which all members are in Open mode), they can approve and welcome the peer directly.

The mode is selected at network creation:

```bash
sudo pitopi create --name gaming --mode open
```

### The MembershipPolicy trait

Authorization is abstracted behind a trait:

```rust
pub trait MembershipPolicy: Send + Sync {
    fn can_authorize(&self, acceptor: &Member) -> bool;
}
```

Two implementations exist:

- `OpenPolicy` -- always returns `true`. Any member can accept new peers.
- `RestrictedPolicy` -- returns `true` only if `acceptor.is_coordinator` is `true`.

The `policy_for_mode()` function creates the right policy for a given `GroupMode`:

```rust
pub fn policy_for_mode(mode: GroupMode) -> Box<dyn MembershipPolicy> {
    match mode {
        GroupMode::Open => Box::new(OpenPolicy),
        GroupMode::Restricted => Box::new(RestrictedPolicy),
    }
}
```

---

## 5. Transport

**Module:** `src/transport.rs`

The transport layer wraps iroh's `Endpoint` to provide peer-to-peer QUIC connectivity with automatic NAT traversal.

### Endpoints

An iroh `Endpoint` is the local end of the P2P network. It binds to a UDP socket, registers with iroh's relay infrastructure for peer discovery, and handles NAT hole-punching. A single endpoint can serve multiple networks simultaneously by accepting connections on different ALPNs.

The endpoint is created with:
- The node's `SecretKey` (Ed25519 private key)
- A list of ALPNs (one per network the node participates in)

### ALPN-based network isolation

Each pitopi network gets its own ALPN (Application-Layer Protocol Negotiation) string:

```
pitopi/net/<network-name>
```

For example, `pitopi/net/gaming` or `pitopi/net/work`. When a connection arrives, pitopi checks the ALPN to determine which network it belongs to and routes it accordingly.

This allows a single iroh endpoint to participate in multiple networks without interference. Connection attempts for one network are invisible to another.

### Connection model

Pitopi uses two types of QUIC channels:

1. **Bidirectional streams** -- for control messages (join requests, member syncs, mesh hellos). These are reliable and ordered, suitable for the structured JSON messages that coordinate membership.

2. **Datagrams** -- for data packets (the actual network traffic tunneled through the VPN). These are unreliable and unordered, providing the lowest possible latency.

### NAT traversal

iroh handles NAT traversal automatically. The typical flow:

1. Peers register with relay servers, which store their contact information.
2. When peer A wants to connect to peer B, it looks up B's relay information.
3. iroh attempts direct UDP hole-punching between the two peers.
4. If direct connection fails (about 10% of cases), traffic flows through the relay server, still fully encrypted end-to-end.

This means pitopi works without any port forwarding, dynamic DNS, or firewall configuration.

---

## 6. Control Protocol

**Module:** `src/control.rs`

The control protocol handles all coordination between peers: join requests, membership updates, and mesh formation. Messages are sent as length-prefixed JSON over QUIC bidirectional streams.

### Wire format

```
[4 bytes: big-endian u32 length] [N bytes: JSON body]
```

The 4-byte length prefix allows the receiver to know exactly how many bytes to read for each message. Maximum message size is 64 KB.

### Message types

#### Welcome

Sent by any peer to a newly connecting approved peer. This is the primary join message in the gatekeeper model:

```json
{
    "Welcome": {
        "members": [
            { "identity": "abc123...", "ip": "100.64.10.5", "is_coordinator": true },
            { "identity": "def456...", "ip": "100.64.23.142", "is_coordinator": false }
        ],
        "approved": [
            { "identity": "jkl012...", "ip": "100.64.7.99" }
        ],
        "membership_dht_id": "abc123..."
    }
}
```

The `members` list contains every current member. The `approved` list contains peers that have been approved but haven't connected yet. The `membership_dht_id` (optional) is the hex-encoded public key of the coordinator's per-network DHT signing key — peers use this to resolve membership from the pkarr relay when the coordinator is offline. The joiner checks its own derived IP against the member list for collision detection.

#### MemberApproved

Broadcast by the coordinator to all connected peers when a new identity is approved:

```json
{
    "MemberApproved": {
        "identity": "def456...",
        "ip": "100.64.23.142"
    }
}
```

Receiving peers add this entry to their local `ApprovedList`. When the approved peer later connects to any of them, they can welcome that peer without needing the coordinator to be online.

#### JoinApproved (legacy)

The original join message, retained for backward compatibility with older peers:

```json
{
    "JoinApproved": {
        "your_ip": "100.64.23.142",
        "members": [
            { "identity": "abc123...", "ip": "100.64.10.5", "is_coordinator": true },
            { "identity": "def456...", "ip": "100.64.23.142", "is_coordinator": false }
        ]
    }
}
```

New coordinators send `Welcome` instead. Joiners accept both formats.

#### JoinDenied

Sent when a join is rejected:

```json
{
    "JoinDenied": {
        "reason": "IP collision"
    }
}
```

Reasons include "not authorized" (policy rejection) and "IP collision: 100.64.x.x already assigned" (hash collision with an existing member or approved peer).

#### MemberSync

Broadcast to all existing peers when the member list changes. Also sent to reconnecting peers:

```json
{
    "MemberSync": {
        "members": [
            { "identity": "abc123...", "ip": "100.64.10.5", "is_coordinator": true },
            { "identity": "def456...", "ip": "100.64.23.142", "is_coordinator": false },
            { "identity": "ghi789...", "ip": "100.64.7.42", "is_coordinator": false }
        ],
        "membership_dht_id": "abc123..."
    }
}
```

This is the primary mechanism for keeping all peers' view of the network in sync. The optional `membership_dht_id` field carries the coordinator's DHT signing key so peers can resolve membership from the pkarr relay.

#### MeshHello

Sent by a newly joining peer to each existing mesh member to establish a direct connection:

```json
{
    "MeshHello": {
        "identity": "def456...",
        "ip": "100.64.23.142"
    }
}
```

The receiving peer adds the sender to its routing table and spawns a datagram reader for the connection.

#### MeshWelcome

The response to a `MeshHello`:

```json
{
    "MeshWelcome": {
        "identity": "abc123...",
        "ip": "100.64.10.5"
    }
}
```

#### ReconnectRequest

Sent by a peer that was previously a member and is reconnecting after a disconnection:

```json
{
    "ReconnectRequest": {
        "identity": "def456...",
        "ip": "100.64.23.142"
    }
}
```

The receiving peer checks whether the sender is in the known member list. If so, it adds them to the routing table and sends back a `MemberSync` with the current member list. If not, the request is rejected.

#### AdvertiseServices

Allows peers to announce services they're running:

```json
{
    "AdvertiseServices": {
        "ip": "100.64.10.5",
        "services": [
            { "name": "minecraft", "port": 25565 }
        ]
    }
}
```

This is defined in the protocol but not yet integrated into the CLI.

### Identity verification

When a peer sends a `MeshHello` or `ReconnectRequest`, the receiving peer verifies that the claimed `identity` field matches the QUIC connection's transport-level identity (`conn.remote_id()`). This prevents a peer from impersonating another member by sending a forged identity in the control message.

---

## 7. TUN Device

**Module:** `src/tun.rs`

A TUN (network TUNnel) device is a virtual network interface that operates at the IP layer. Unlike a TAP device (which works at the Ethernet layer), a TUN device sends and receives raw IPv4 packets without Ethernet framing.

### Creation

Pitopi creates a TUN device with:

- **Address:** the peer's identity-derived IP (e.g., `100.64.23.142`)
- **Gateway/destination:** `100.64.0.1` (fixed for point-to-point interface on macOS)
- **Netmask:** `255.192.0.0` (/10, covering the entire CGNAT range)
- **MTU:** 1200 bytes

The /10 netmask means the operating system routes all traffic destined for `100.64.0.0` through `100.127.255.255` to this TUN device. Any application sending to a peer's virtual IP will have its packets captured by pitopi.

### MTU

The MTU is set to 1200 bytes, which is conservative but ensures packets fit within QUIC datagram limits. QUIC datagrams are themselves carried over UDP, which sits on top of IP. With typical path MTUs of 1280-1500 bytes, 1200 leaves comfortable room for QUIC, UDP, and IP headers without fragmentation.

### Async I/O

The TUN device is split into separate `TunReader` and `TunWriter` halves using the `tun` crate's `AsyncDevice::split()` method. This allows the read loop (outgoing packets) and write path (incoming packets) to operate concurrently without any locking.

```rust
pub struct TunReader {
    reader: DeviceReader,
}

pub struct TunWriter {
    writer: DeviceWriter,
}
```

This split/sink pattern is critical for performance — sharing an I/O device behind a Mutex serializes reads and writes, causing packet buffering and latency spikes. With separate halves, outgoing packets can be read from TUN simultaneously with incoming packets being written to TUN.

### Platform differences

**macOS (utun):** TUN devices are point-to-point interfaces that require a destination address. The `destination(100.64.0.1)` configuration satisfies this requirement.

**Linux (/dev/net/tun):** TUN devices are created through the standard Linux TUN/TAP driver. The `ensure_root_privileges(true)` platform configuration is set.

### Single TUN architecture

Pitopi uses a single TUN device per node, shared across all networks. Since all networks use the flat `100.64.0.0/10` address space and each peer has a globally unique identity-derived IP, there is no address conflict between networks. Packets are demultiplexed by looking up the destination IP in a shared routing table.

---

## 8. Packet Forwarding

**Module:** `src/forward.rs`

The forwarding module is the data plane of pitopi. It moves packets between the TUN device and peer QUIC connections.

### Architecture

Three concurrent tasks handle forwarding, with the TUN device split into separate read and write halves for lock-free I/O:

```
TunReader                     Peer connections
    |                              |
    v                              v
run_mesh()                    spawn_peer_reader() [one per peer]
  reads packets from TUN        reads datagrams from QUIC
  looks up dest IP               sends packets via tun_tx channel
  sends datagram to peer              |
                                      v
                              spawn_tun_writer(TunWriter)
                                writes packets to TUN
```

### TUN read loop (`run_mesh`)

This is the main forwarding loop. It reads packets from the TUN device in a tight loop:

1. Read a packet from TUN into a 1500-byte buffer.
2. Extract the destination IP from bytes 16-19 of the IPv4 header.
3. Look up the destination IP in the `PeerTable`.
4. If found, send the packet as a QUIC datagram on that peer's connection.
5. If not found (unknown destination), record a dropped packet in stats.

The function takes ownership of the `TunReader` half:

```rust
pub async fn run_mesh(
    mut tun: TunReader,
    peers: PeerTable,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()>
```

### Peer readers (`spawn_peer_reader`)

Each peer connection gets a dedicated reader task that receives QUIC datagrams and forwards them to the TUN device:

1. Wait for a datagram from the peer's QUIC connection.
2. Send the raw packet bytes through the `tun_tx` channel to the TUN writer.
3. Record received bytes in stats.

If the connection drops, the reader sends a `DisconnectEvent` (containing the peer's `EndpointId` and IP) on the disconnect channel and exits. This triggers automatic reconnection on the joiner side (see below).

### TUN writer (`spawn_tun_writer`)

A single task reads from the `tun_rx` channel and writes packets to the TUN device. This serializes writes to the TUN, avoiding concurrent access.

### Destination IP extraction

The `dest_ip()` function reads the destination address directly from the IPv4 header:

```rust
fn dest_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 { return None; }    // minimum IPv4 header
    if packet[0] >> 4 != 4 { return None; }  // must be IPv4
    Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}
```

Bytes 16-19 of an IPv4 header contain the 32-bit destination address. The function also validates that the packet is long enough to contain a complete header and that the version nibble indicates IPv4.

---

## 9. Peer Table

**Module:** `src/peers.rs`

The `PeerTable` is the routing table that maps virtual IP addresses to QUIC connections. When the forwarding loop needs to send a packet, it looks up the destination IP here to find the right connection.

### Structure

```rust
pub struct PeerTable {
    inner: Arc<RwLock<HashMap<Ipv4Addr, PeerEntry>>>,
}

pub struct PeerEntry {
    pub conn: Connection,
    pub endpoint_id: EndpointId,
}
```

Each entry maps an IP address to:
- The QUIC `Connection` object used to send datagrams to that peer.
- The peer's `EndpointId` for identification.

### Thread safety

The table is wrapped in `Arc<RwLock<...>>` using the standard library's `RwLock`. This allows:
- Multiple concurrent readers (the forwarding loop and any task checking membership)
- Exclusive writes (adding or removing peers)

The `PeerTable` implements `Clone` by cloning the `Arc`, so all clones share the same underlying data. This is how it's shared between the forwarding loop, accept loop, and mesh acceptor.

### Operations

- `add(ip, conn, endpoint_id)` -- insert or replace a peer entry.
- `remove(ip)` -- remove a peer and return their connection.
- `lookup(ip)` -- find the connection for a given IP (used by the forwarding loop on every packet).
- `all_connections()` -- list all peers (used for broadcasting MemberSync messages).
- `all_peer_ids()` -- list all peers with their identity strings.

### Shared across networks

In the `cmd_up` path (connecting to all saved networks), a single `PeerTable` is shared across all networks. Since the address space is flat (`100.64.0.0/10`) and each peer has a globally unique identity-derived IP, there is no ambiguity -- a given IP always maps to exactly one peer.

---

## 10. Configuration

**Module:** `src/config.rs`

Pitopi persists network memberships to `~/.config/pitopi/networks.toml` so that networks survive restarts. The `pitopi up` command reads this file to reconnect to all saved networks.

### File format

```toml
[[networks]]
name = "gentle-amber-fox"
group_mode = "open"
my_ip = "100.64.23.142"
network_pkarr_pubkey = "abc123def456..."
membership_dht_pubkey = "def456ghi789..."

[[networks.members]]
identity = "abc123def456..."
ip = "100.64.10.5"
is_coordinator = true

[[networks.members]]
identity = "def456ghi789..."
ip = "100.64.23.142"
is_coordinator = false

[[networks.approved]]
identity = "jkl012abc345..."
ip = "100.64.7.99"

[[networks]]
name = "work"
group_mode = "restricted"
network_pkarr_pubkey = "xyz789..."
membership_dht_pubkey = "uvw012..."
```

### Data model

**AppConfig** -- the top-level container:
```rust
pub struct AppConfig {
    pub networks: Vec<NetworkConfig>,
}
```

**NetworkConfig** -- a single network membership:
```rust
pub struct NetworkConfig {
    pub name: String,                              // three-word network name
    pub group_mode: GroupMode,                     // Open or Restricted
    pub my_ip: Option<Ipv4Addr>,                  // our IP (None if we're the coordinator)
    pub members: Vec<MemberEntry>,                 // connected members
    pub approved: Vec<ApprovedConfigEntry>,        // approved but not yet connected
    pub network_pkarr_pubkey: Option<String>,      // DHT public key for seed list record
    pub membership_dht_pubkey: Option<String>,     // DHT public key for membership blob hash
}
```

Note: `coordinator_id` was removed. The coordinator is identified by `is_coordinator: true` in the members list. The two DHT pubkeys are used for the directory → seed list → membership three-step lookup.

**MemberEntry** -- a connected member:
```rust
pub struct MemberEntry {
    pub identity: EndpointId,  // iroh public key
    pub ip: Ipv4Addr,          // identity-derived IP
    pub is_coordinator: bool,  // whether this member is the coordinator
}
```

**ApprovedConfigEntry** -- a pre-approved peer:
```rust
pub struct ApprovedConfigEntry {
    pub identity: EndpointId,  // iroh public key
    pub ip: Ipv4Addr,          // identity-derived IP
}
```

The `approved` and `membership_dht_id` fields use `#[serde(default)]`, so config files written by older versions (without these fields) still deserialize correctly.

### Coordinator vs. member

The `my_ip` field distinguishes the coordinator from members:
- **Coordinator:** `my_ip` is `None`. The coordinator doesn't need to store their own IP separately because they know it from their identity.
- **Member:** `my_ip` is `Some(ip)`. This is the IP confirmed during the join handshake.

This distinction drives `cmd_up` behavior -- coordinators start an accept loop, members connect to the coordinator.

### Operations

- `load()` -- read the config file, or return a default empty config if it doesn't exist.
- `save(config)` -- write the config to disk as pretty-printed TOML.
- `upsert_network(config, network)` -- add a network or replace an existing one with the same name.
- `remove_network(config, name)` -- remove a network by name.

### When config is written

Config is written at several points:
1. **Create:** when the coordinator creates a network (saves self as the only member, empty approved list).
2. **Join:** when a peer receives `Welcome` or `MemberSync` (saves both the member list and approved list).
3. **Accept loop:** when the coordinator approves a new peer or promotes an approved peer to member.
4. **Leave:** when the user runs `pitopi leave` (removes the network entry).

---

## 11. Three-Word Names

**Module:** `src/network_name.rs`

EndpointIds are 32-byte binary values, far too unwieldy to share with friends. Pitopi solves this with randomly generated three-word names in the format `adjective-noun-noun` (e.g., `gentle-amber-fox`). These names are memorable, speakable, and easy to share over chat or voice.

### Generation

`generate_name()` selects one word from each of three embedded word lists (adjectives, first-nouns, second-nouns) using a cryptographically random index:

```rust
pub fn generate_name() -> String {
    // Uses rand::random to pick indices into embedded word lists
    // Returns "adjective-noun-noun"
}
```

The word lists are embedded at compile time. The combination space is large enough that collisions are extremely rare for typical usage.

### Validation

`is_valid_name(s: &str) -> bool` checks that a string matches the three-word format (all lowercase, hyphen-separated, each word from the known lists). This is used to validate user input on `pitopi join`.

### How names replace room codes

Previously, `pitopi join` required a room code containing the coordinator's EndpointId:

```
gaming/ybnj-raqe-c5s6-k7mp-...
```

Now, the name is self-sufficient for joining because the DHT stores a directory record mapping the name to the network's keys:

```
gentle-amber-fox   →   (network_pkarr_pubkey, membership_dht_pubkey)
```

From those keys the joiner can resolve the seed list and membership blob without knowing the coordinator's EndpointId in advance. This makes pitopi fully coordinator-optional from the user's perspective: once the network is created and the name is shared, the coordinator can go offline and new peers can still join through the mesh.

---

## 12. Access Control

**Module:** `src/acl.rs`

Pitopi supports distributed, identity/tag-based ACLs. The coordinator manages allow rules that are published to all peers and enforced at the packet forwarding layer.

### Policy model

ACLs are allow-only. The semantics are simple:

- **No rules:** all traffic is allowed (open network).
- **Any rules:** only explicitly allowed traffic passes; everything else is denied.

This is an intentionally conservative model: the moment you add any rule, the default becomes deny-all.

ACLs are enforced at the forwarding layer on every peer:
- **Outbound** (`run_mesh`): packets read from the TUN device are checked before being sent to the destination peer.
- **Inbound** (`spawn_peer_reader`): packets received from peers are checked before being written to the local TUN device.

Control traffic (QUIC streams for membership, mesh hello, etc.) is always exempt — ACLs only filter data-plane packets tunneled through the TUN device.

### Tags

Tags are named labels that group peers. They enable group-based rules without listing individual endpoint IDs:

```
pitopi acl gentle-amber-fox tag servers ab3f... d92c...
# assigns the "servers" tag to two peers

pitopi acl gentle-amber-fox allow servers servers
# allow all tagged servers to reach each other
```

Targets in allow rules can be:
- A tag name (e.g., `servers`) — matches any peer with that tag
- `all` — matches any peer in the network
- An endpoint ID prefix — matches a specific peer

### CLI commands

All ACL commands are scoped to a network. Only the coordinator should modify ACLs; peers apply coordinator-published changes.

```bash
# Assign tags to peers (by endpoint ID prefix)
pitopi acl gentle-amber-fox tag servers ab3f... d92c...

# Remove a tag from peers
pitopi acl gentle-amber-fox untag servers ab3f...

# Add an allow rule: src dst
pitopi acl gentle-amber-fox allow servers servers
pitopi acl gentle-amber-fox allow all servers

# Remove a rule by index (shown in 'show' output)
pitopi acl gentle-amber-fox remove 0

# Show current ACL state
pitopi acl gentle-amber-fox show

# Re-publish the current ACL to all peers (force push)
pitopi acl gentle-amber-fox apply
```

### File format

ACLs are persisted to `~/.config/pitopi/acl/<network>.acl` as a plain-text file:

```
tag servers ab3f1234... d92c5678...
tag admins aa11...
allow servers -> servers
allow admins -> all
```

Lines starting with `tag` define tag assignments. Lines starting with `allow` define rules. The file is reloaded on daemon startup.

### Distribution

ACL state is distributed using the same iroh-blobs + pkarr pattern as membership:

1. Coordinator serializes `AclData` to canonical msgpack, hashes with blake3.
2. Publishes the hash to the ACL pkarr record (4th record type, keyed by `derive_acl_key`).
3. Broadcasts an `AclUpdated { acl_hash }` control message to all connected peers.
4. Peers receive `AclUpdated`, fetch the blob from the coordinator via iroh-blobs, verify the blake3 hash, and load the new ACL into memory.

On join, the Welcome message includes `acl_dht_id` so new peers can fetch the current ACL from the DHT even if they missed the broadcast.

### Data structures

```rust
pub struct AclData {
    pub tags: Vec<TagAssignment>,   // peer → tag label mappings
    pub rules: Vec<AclRule>,        // ordered allow rules
}

pub struct TagAssignment {
    pub tag: String,
    pub peers: Vec<EndpointId>,
}

pub struct AclRule {
    pub src: AclTarget,
    pub dst: AclTarget,
}

pub enum AclTarget {
    EndpointId(EndpointId),
    Tag(String),
    All,
}
```

### Example: server network

```bash
# Tag all game servers
pitopi acl gaming tag servers server1... server2... server3...

# Allow all members to reach servers
pitopi acl gaming allow all servers

# Allow servers to reach each other (for replication)
pitopi acl gaming allow servers servers

# Result: regular members cannot reach each other directly —
# all traffic must go through a server
```

---

## 13. Audit Logging

**Module:** `src/audit.rs`

The audit module provides an append-only log of peer connection events at `~/.config/pitopi/audit.log`.

### Format

Each line is a tab-separated record:

```
1719835423  connect     100.64.23.142  abc123def456...
1719835430  disconnect  100.64.23.142  abc123def456...
```

Fields:
1. Unix timestamp (seconds since epoch)
2. Event type (`connect` or `disconnect`)
3. Peer's virtual IP
4. Peer's EndpointId

### Thread safety

The log file is wrapped in a `std::sync::Mutex` to allow safe concurrent writes from multiple async tasks:

```rust
pub struct AuditLog {
    file: Mutex<std::fs::File>,
}
```

Writes use `OpenOptions::append(true)`, so even if multiple processes write concurrently, individual records won't be corrupted (append writes are atomic on most filesystems for small writes).

### Current status

The audit log infrastructure is built but not yet wired into the main connection lifecycle. The API is ready:

```rust
audit.log_connect(peer_ip, &endpoint_id);
audit.log_disconnect(peer_ip, &endpoint_id);
```

---

## 14. Statistics

**Module:** `src/stats.rs`

The stats module tracks packet and byte counters for monitoring forwarding performance.

### Counters

Five atomic counters track activity:

| Counter | Meaning |
|---------|---------|
| `packets_rx` | Packets received from peers |
| `packets_tx` | Packets sent to peers |
| `bytes_rx` | Total bytes received |
| `bytes_tx` | Total bytes sent |
| `drops` | Packets that couldn't be routed (unknown destination or send failure) |

All counters use `AtomicU64` with `Ordering::Relaxed`, since exact ordering between counters isn't important for monitoring.

### Periodic logging

The `spawn_logger` method starts a background task that logs stats every 30 seconds as deltas (not cumulative totals). This shows recent activity rather than all-time totals:

```
INFO (30s) rx=42 tx=38 bytes_rx=49356 bytes_tx=44100 drops=0
```

Byte counts are logged as raw values (no formatting) for easy parsing and scripting.

---

## 15. Shutdown

**Module:** `src/shutdown.rs`

Pitopi uses a `CancellationToken` from `tokio-util` for coordinated shutdown. Every long-running task (forwarding loops, accept loops, peer readers, stats logger) checks this token and exits cleanly when it's cancelled.

### Signal handling

The `token()` function creates a `CancellationToken` and spawns a task that waits for a shutdown signal:

- **Unix (macOS/Linux):** listens for both `SIGINT` (Ctrl+C) and `SIGTERM`.
- **Windows:** listens for Ctrl+C only.

When the signal arrives, the token is cancelled, and all tasks that are `tokio::select!`-ing on `token.cancelled()` exit their loops and clean up.

### Shutdown flow

```
SIGINT/SIGTERM received
    |
    v
CancellationToken cancelled
    |
    +-- run_mesh() returns Ok(())
    +-- run_accept_loop() returns Ok(())
    +-- spawn_peer_reader() returns
    +-- spawn_logger() prints session summary, returns
    |
    v
main() returns
```

The shutdown is cooperative, not forceful. Each task exits at its next `tokio::select!` checkpoint, which ensures no packets are lost mid-send and all resources are released cleanly.

---

## 16. DHT Membership

**Module:** `src/dht.rs`

Pitopi publishes network membership and ACL data to iroh's pkarr relay so that peers can discover each other and fetch policy even when the coordinator is offline. Four pkarr record types work together to enable coordinator-free joins starting from just a three-word name.

### Four-record model

```
  User types:  "gentle-amber-fox"
                    |
                    v
  [1] Directory record  (keyed by blake3 hash of network name)
        → network_pkarr_pubkey
        → membership_dht_pubkey
                    |
          .---------+---------.
          |                   |
          v                   v
  [2] Seed list record    [3] Membership record    [4] ACL record
      (keyed by              (keyed by                (keyed by
       network_pkarr_pubkey)  membership_dht_pubkey)   acl_dht_pubkey)
        → online peer          → blake3 hash of         → blake3 hash of
          EndpointIds            canonical member blob    canonical ACL blob
                    |                   |                       |
                    '------- all -------+----------- -----------'
                                |
                                v
                    fetch blobs from any seed peer
                    verify blake3 hashes
                    get full member + approved lists + ACL rules
```

#### Record 1: Directory record

Maps a human-readable name to the two DHT public keys needed to look up the rest of the network data:

```rust
pub fn derive_directory_key(network_name: &str) -> SecretKey { ... }
pub fn directory_dht_id(network_name: &str) -> PublicKey { ... }
pub fn encode_directory_record(...) -> SignedPacket { ... }
pub fn decode_directory_record(packet: &SignedPacket) -> Result<(PublicKey, PublicKey)> { ... }
pub async fn publish_directory(...) -> Result<()> { ... }
pub async fn resolve_directory(network_name: &str) -> Result<(PublicKey, PublicKey)> { ... }
```

The directory key is derived from `blake3::hash("pitopi/directory/{network_name}")`. Any peer that knows the network name can look this up — no coordinator needed. Different names produce different keys, so networks don't collide in the DHT.

#### Record 2: Seed list record

Maps the `network_pkarr_pubkey` to a list of currently online peer `EndpointId`s:

```rust
pub fn encode_seed_list_record(peers: &[EndpointId], key: &SecretKey) -> SignedPacket { ... }
pub fn decode_seed_list_record(packet: &SignedPacket) -> Result<Vec<EndpointId>> { ... }
pub async fn publish_seed_list(peers: &[EndpointId], key: &SecretKey) -> Result<()> { ... }
pub async fn resolve_seed_list(pubkey: &PublicKey) -> Result<Vec<EndpointId>> { ... }
```

The `network_pkarr_pubkey` key is derived from the `network_secret` (a random 32-byte value generated at create time). Because `network_secret` is embedded in the membership blob, all online peers can re-publish the seed list — it's not exclusively the coordinator's job. `spawn_seed_list_publisher()` refreshes this record every 300 seconds.

#### Record 3: Membership record

Maps the `membership_dht_pubkey` to a blake3 hash of the canonical membership blob:

```
"v1"                        // version sentinel (always first)
"h,<blake3_hex>"            // hash of canonical msgpack-serialized MembershipData
```

The full membership data is serialized as msgpack (sorted by identity for determinism) and stored in each peer's iroh-blobs store (`FsStore`). Every peer serves blobs via the iroh-blobs protocol (`/iroh-bytes/4` ALPN). The record contains only the hash — not member entries — keeping it well within DNS TXT record size limits regardless of network size.

`MembershipData` now includes `network_secret` and `membership_signing_key` fields so peers receiving it can independently publish seed list records and verify DHT keys.

#### Record 4: ACL record

Maps the `acl_dht_pubkey` (derived from the coordinator's secret key + network name via `blake3::derive_key("pitopi/acl/...")`) to a blake3 hash of the canonical ACL blob:

```rust
pub fn derive_acl_key(coordinator_key: &SecretKey, network_name: &str) -> SecretKey { ... }
pub fn acl_dht_id(coordinator_key: &SecretKey, network_name: &str) -> PublicKey { ... }
pub async fn publish_acl(acl: &AclData, key: &SecretKey) -> Result<()> { ... }
pub async fn resolve_acl_hash(pubkey: &PublicKey) -> Result<Hash> { ... }
```

The full ACL blob is serialized as msgpack (sorted for determinism) and stored in the iroh-blobs store. The record contains only the hash. Peers receive `AclUpdated` pushes in real time; the DHT record is a fallback for joiners and reconnecting peers. Only the coordinator can publish ACL updates (only they hold the `coordinator_key`).

### Membership data exchange via iroh-blobs

Joiners fetch the full membership via iroh-blobs:

1. Resolve the directory record to get `(network_pkarr_pubkey, membership_dht_pubkey)`.
2. Resolve seed list and membership hash **in parallel**.
3. For each seed peer endpoint, try `try_fetch_blob_from_peer(endpoint_id, hash)`.
4. Verify `blake3::hash(bytes) == hash` before trusting the data.
5. Deserialize `MembershipData` to get member list, approved list, secrets, and signing keys.

### Publishing

Three background tasks keep DHT records fresh:

**Membership publisher** (`spawn_dht_publisher`):
- Publishes immediately on startup
- Re-publishes on membership changes (via `tokio::sync::Notify`)
- Re-publishes every 5 minutes as a periodic refresh

**Seed list publisher** (`spawn_seed_list_publisher`):
- Publishes the current list of online peer EndpointIds every 300 seconds
- Any peer (not just the coordinator) can run this task

**Membership poller** (`spawn_membership_poller`):
- Checks the membership hash via pkarr every 60 seconds
- If the hash changed (new members approved while offline), fetches the new blob and reconciles the member/approved lists

Publishing errors are logged as warnings and never crash the coordinator or block the accept loop.

### Three-step join resolution

When `pitopi join gentle-amber-fox` is run:

1. **Directory lookup:** resolve `directory_dht_id("gentle-amber-fox")` → `(network_pkarr_pubkey, membership_dht_pubkey)`.
2. **Parallel resolution:** simultaneously resolve seed list (→ online peer endpoints) and membership hash (→ blake3 hash of blob).
3. **Blob fetch:** connect to seed peers one by one via `try_fetch_blob_from_peer()` until one responds. Verify hash, deserialize.
4. **Mesh join:** use member/approved lists from blob to connect to coordinator or any peer in the mesh.

This is best-effort: if any step fails, pitopi falls back to local config. If all fail, the join fails with an error explaining what went wrong.

### Security

- **Directory records** are keyed by a hash of the public network name — anyone can look up a network by name, but nobody can forge the record since it's not signed by a secret key (the key is deterministic from the name).
- **Seed list records** are signed by `network_pkarr_pubkey`, derived from `network_secret`. Only peers that have joined the network (and received the membership blob containing `network_secret`) can publish seed lists.
- **Membership records** are signed by `membership_dht_pubkey`, derived from the coordinator's secret key. Only the coordinator can publish membership updates.
- Joiners verify the blake3 hash of the membership blob before trusting any data from it.

---

## 17. Network Lifecycle

This chapter ties the modules together by walking through the complete lifecycle of a network.

### Creating a network

When a user runs `pitopi create` (optionally with `--mode open`), the CLI sends an `IpcRequest::Create` to the daemon. The daemon:

1. **Generate three-word name.** Call `network_name::generate_name()` to produce a random adjective-noun-noun name like `gentle-amber-fox`.

2. **Check not duplicate.** Verify no network with that name is already active (retry generation if needed).

3. **Create identity provider.** Wrap the public key in `IrohIdentityProvider`, which derives the coordinator's virtual IP.

4. **Generate network secret.** Create a random `network_secret: [u8; 32]` (used to sign seed list records).

5. **Derive DHT keys.** Use `blake3::derive_key` to derive `membership_signing_key` from the coordinator's secret key + network name.

6. **Update ALPNs.** Call `endpoint.set_alpns()` to add `pitopi/net/<name>` to the shared endpoint.

7. **Initialize membership.** Create a `MemberList` with self as the only member (marked `is_coordinator: true`). Create the membership policy based on the mode.

8. **Publish to DHT.** Publish directory record (name → keys), seed list record (no peers yet), and membership record (hash of initial member list) to pkarr.

9. **Start DHT publishers.** Spawn `spawn_dht_publisher` (membership, on change + every 5 min) and `spawn_seed_list_publisher` (online peers, every 300s).

10. **Create NetworkHandle.** Insert into the daemon's `networks` map with a child `CancellationToken` and the `network_secret` + `membership_signing_key`.

11. **Save config.** Write the network to `~/.config/pitopi/networks.toml` with `network_pkarr_pubkey` and `membership_dht_pubkey`.

12. **Return response.** Send `IpcResponse::Created` with the generated name and IP back to the CLI.

### Joining a network

When a user runs `pitopi join gentle-amber-fox`, the CLI sends an `IpcRequest::Join { name: "gentle-amber-fox" }` to the daemon. The daemon:

1. **Directory DHT lookup.** Call `dht::resolve_directory("gentle-amber-fox")` to get `(network_pkarr_pubkey, membership_dht_pubkey)`.

2. **Parallel resolution.** Simultaneously resolve the seed list (online peer endpoints) and the membership hash from pkarr.

3. **Fetch membership blob.** Try each seed peer endpoint via `try_fetch_blob_from_peer()` until one responds. Verify the blake3 hash matches before trusting the data. Deserialize to get `MembershipData` (members, approved, network_secret, membership_signing_key).

4. **Update ALPNs.** Call `endpoint.set_alpns()` to add the network's ALPN.

5. **Connect to coordinator or mesh peer.** Use the member list from the blob to find a reachable peer. The first attempt goes to the coordinator. If offline, try other mesh peers.

6. **Receive welcome.** Wait for a `Welcome` message with the current member list, approved list, and DHT IDs.

7. **Check for IP collision.** The joiner checks its own derived IP against the received member list. If a different identity already occupies the same IP, the joiner bails out with an error.

8. **Connect to mesh.** For each member in the list (excluding self and the peer who sent the Welcome), open a QUIC connection and send `MeshHello`.

9. **Start tasks.** Spawn per-peer readers, reconnect loop, seed list publisher, and membership poller.

10. **Create NetworkHandle.** Insert into the daemon's `networks` map.

11. **Save config.** Write the network membership, approved list, `network_pkarr_pubkey`, and `membership_dht_pubkey` to disk.

12. **Return response.** Send `IpcResponse::Joined` with assigned IP back to the CLI.

### Nuking a network

When a user runs `pitopi nuke gentle-amber-fox`, the CLI sends an `IpcRequest::Nuke { name, force }` to the daemon. The daemon:

1. **Publish empty records.** Publish an empty seed list record (no online peers) and an empty membership record to pkarr. This signals to any future joiner that the network is gone.

2. **Leave network.** Cancel the per-network `CancellationToken`, wait for tasks to finish, remove peers from `PeerTable`, remove the ALPN, and delete the config entry.

The `--force` flag skips any confirmation prompt. Without it, the CLI asks the user to confirm before proceeding.

### Coordinator's accept loop

The coordinator runs continuously, accepting incoming connections. It now acts as a pure gatekeeper -- approving identities and broadcasting approvals, rather than being the sole welcome point:

1. **Accept connection.** Wait for an incoming QUIC connection with the right ALPN.

2. **Check identity.** Derive the peer's IP from their EndpointId.

3. **Case 1 -- Known member reconnecting.** If the peer is already in the member list, send them a `MemberSync` with the current member list, add them to the routing table, and spawn a reader.

4. **Case 2 -- Approved peer connecting.** If the peer is in the approved list (approved earlier but connecting now), send a `Welcome` with the member list and approved list, promote from approved to full member, broadcast `MemberSync` to all existing peers, and spawn a reader.

5. **Case 3 -- Unknown peer.** Check the `MembershipPolicy`. If not authorized, send `JoinDenied`. If authorized:
   a. **Check IP collision** against both the member list and approved list. If collision, send `JoinDenied`.
   b. **Broadcast `MemberApproved`** to all connected peers so they add the identity to their approved lists.
   c. **Immediately promote** the peer to full member (since they're already connected).
   d. **Send `Welcome`** with the member list and approved list.
   e. **Broadcast `MemberSync`** to all existing peers and spawn a reader.

### Any-peer welcome

Every peer in the mesh can welcome approved peers, not just the coordinator. The mesh acceptor handles incoming connections:

1. **Verify identity.** Check that the `MeshHello` identity matches `conn.remote_id()`.

2. **Approved peer?** If the connecting peer is in the local approved list, send a `Welcome` with the member list and approved list, promote from approved to member, and broadcast `MemberSync`.

3. **Known member?** If the peer is already a member, add them to the routing table (reconnection).

4. **Unknown peer?** Reject the connection. Unknown peers must go through the coordinator (or any authorizing peer in Open mode) first.

### Reconnecting after disconnection

Reconnection operates at two levels:

#### Per-peer reconnection (within a mesh session)

When a single peer's connection drops while the mesh is running:

1. **Detect disconnection.** The peer reader task's `conn.read_datagram()` returns an error. It sends a `DisconnectEvent` on an mpsc channel and exits.

2. **Coordinator side (`spawn_peer_cleanup`).** Receives the event and removes the dead peer from the `PeerTable`. The coordinator doesn't actively reconnect — peers reconnect to it.

3. **Joiner side (`spawn_reconnect_loop`).** Receives the event, removes the dead peer from the `PeerTable`, and spawns a per-peer reconnect task with exponential backoff (1s initial, 30s max):
   - Connects to the peer via `transport::connect_to_peer_with_alpn`
   - Sends `MeshHello` to re-establish the relationship
   - Adds the new `Connection` to the `PeerTable`
   - Spawns a fresh `spawn_peer_reader` (which feeds back into the same disconnect channel)

4. **During the gap.** The `PeerTable` has no entry for the disconnected peer's IP, so `run_mesh` silently drops packets destined for it. Once the new connection lands, traffic resumes transparently.

#### Full session reconnection (coordinator/all peers lost)

When the entire mesh session fails (e.g., `enter_mesh` returns an error):

1. **Reconnect loop.** The `cmd_join` function runs in an outer loop with exponential backoff. On disconnection, it:
   - Tries resolving membership from the DHT (if a `membership_dht_id` is saved in config) for a potentially fresher member list.
   - Tries the coordinator first.
   - If the coordinator is unavailable, tries every known peer from the saved config.
   - On successful connection, re-enters the mesh (receives MemberSync, reconnects to peers).

2. **Any peer can help.** Known peers accept reconnection requests because they hold the current member list. This is the "offline coordinator resilience" feature -- if the coordinator goes down, existing members can still reconnect to each other. DHT resolution enhances this by providing a potentially more up-to-date member list than the local config.

### Daemon startup

When a user runs `sudo pitopi daemon` (or `sudo pitopi up`):

1. **Load identity** from `~/.config/pitopi/secret_key`.

2. **Create shared resources.** A single iroh Endpoint, TUN device, PeerTable, and Stats are created and shared across all networks.

3. **Restore saved networks** from config. For each saved network, the daemon calls its internal create or join logic to bring it back up.

4. **Start accept loop.** A shared accept loop dispatches incoming connections by ALPN to the correct network's handler.

5. **Start IPC listener.** Bind the Unix socket at `/var/run/pitopi/pitopi.sock` and accept client commands.

6. **Block on shutdown.** Wait for `CancellationToken` (SIGINT/SIGTERM or `pitopi down`).

All networks share the same TUN device and routing table, since the address space is flat and each peer has a globally unique IP.

---

## 18. Daemon Architecture

Pitopi uses a daemon/client split similar to Tailscale. The daemon (`pitopi daemon`) is a long-lived root process that owns all shared resources, while CLI commands are thin IPC clients.

### Why a daemon?

Without a daemon, each `pitopi create` or `pitopi join` was a blocking process that owned its own iroh endpoint and TUN device. There was no way to:

- Manage multiple networks from a single process
- Query live peer status
- Dynamically create, join, or leave networks at runtime

The daemon solves all three by centralizing resource ownership and accepting commands over IPC.

### Shared state (`DaemonState`)

The daemon holds:

- **`endpoint`** — a single iroh `Endpoint` shared across all networks. ALPNs are updated dynamically via `Endpoint::set_alpns()` when networks are added or removed.
- **`peers`** — a single `PeerTable` shared across all networks. Each `PeerEntry` is tagged with a network name so peers can be cleaned up per-network on leave.
- **TUN device** — a single TUN device with a /10 netmask, shared across all networks.
- **`networks`** — a `HashMap<String, NetworkHandle>` behind `RwLock`, mapping network names to their handles.
- **`shutdown_token`** — master `CancellationToken` for clean shutdown.

### Per-network state (`NetworkHandle`)

Each active network has:

- **`cancel`** — a child `CancellationToken` of the master. Cancelling it tears down only this network's tasks.
- **`tasks`** — `JoinHandle`s for the network's background tasks (DHT publisher, seed list publisher, membership poller, reconnect loop, peer cleanup).
- **`role`** — whether we're the coordinator or a member.
- **`my_ip`** — our virtual IP in this network.
- **`network_secret`** — 32-byte random secret used to sign seed list DHT records.
- **`membership_signing_key`** — 32-byte key derived from coordinator secret key, used to sign membership DHT records.
- **`state`** — the `NetworkState` (member list, approved list, policy).

### IPC protocol

The Unix socket at `/var/run/pitopi/pitopi.sock` uses the same wire format as the peer-to-peer control protocol: 4-byte big-endian length prefix + JSON body. The types are defined in `src/ipc.rs`:

- **`IpcRequest`** — `Create` (no name field), `Join { name }`, `Leave`, `Nuke { name, force }`, `Status`, `Shutdown`
- **`IpcResponse`** — `Ok`, `Error`, `Created` (with generated name + IP), `Joined`, `Status`

The daemon accepts one connection at a time, reads a request, processes it, and sends a response. The CLI helpers (`ipc_create`, `ipc_join`, etc.) in `main.rs` handle the client side.

### Dynamic ALPN management

The key enabler for runtime network management is `Endpoint::set_alpns()`. When a network is created or joined, its ALPN (`pitopi/net/<name>`) is added to the endpoint. When a network is left, the ALPN is removed. The shared accept loop dispatches incoming connections to the correct network handler based on the ALPN.

### Network teardown (`leave`)

When a network is left:

1. Cancel the per-network `CancellationToken` — stops DHT publisher, reconnect loop, and other tasks.
2. Wait for all tasks to complete.
3. Remove peers from the `PeerTable` using `remove_by_network()`.
4. Remove the `NetworkHandle` from the `networks` map.
5. Refresh ALPNs on the endpoint (removing the network's ALPN).
6. Remove the network from config.

---

## 19. Code Flow Diagrams

Visual reference for how data and control flow through the codebase.

### Coordinator startup (`pitopi create`)

```
create_network_inner()
  → network_name::generate_name()         adjective-noun-noun (e.g. gentle-amber-fox)
  → rand::random::<[u8; 32]>()           generate network_secret
  → dht::derive_membership_key()          blake3 derive per-network DHT signing key
  → IrohIdentityProvider::new()            derive virtual IP via FNV-1a
  → MemberList::new() + add(self)          first member (is_coordinator: true)
  → dht::publish_directory(...)           name → (network_pkarr_pubkey, membership_dht_pubkey)
  → dht::publish_seed_list([])            empty seed list (no peers yet)
  → dht::publish_membership(hash)         hash of initial member blob
  → config::save()                         persist to networks.toml
  → tun::create(my_ip)                     create TUN device
     ↓
  (TunReader, TunWriter)                   split immediately, no Mutex
     ↓
  ┌───────────────────────────────────────────────────────────────┐
  │ Background tasks:                                             │
  │                                                               │
  │  forward::spawn_tun_writer(TunWriter, tun_rx)                 │
  │    └ reads packets from channel, writes to TUN                │
  │                                                               │
  │  forward::run_mesh(TunReader, peers, ...)                      │
  │    └ reads packets from TUN, routes via PeerTable              │
  │                                                               │
  │  spawn_dht_publisher(...)                                      │
  │    └ publishes membership hash on change + every 5 min         │
  │                                                               │
  │  spawn_seed_list_publisher(...)                                │
  │    └ publishes online peer endpoints every 300s               │
  │                                                               │
  │  spawn_peer_cleanup(disconnect_rx, peers)                      │
  │    └ removes dead peers from PeerTable on disconnect          │
  └───────────────────────────────────────────────────────────────┘
     ↓
  run_accept_loop()                        blocks here
    loop {
      conn = accept_connection_with_alpn()
      remote_id = conn.remote_id()
      peer_ip = derive_ip(remote_id)

      Case 1: known member
        → send MemberSync, add to PeerTable, spawn_peer_reader

      Case 2: approved peer
        → promote to member, send Welcome, broadcast MemberSync,
          add to PeerTable, spawn_peer_reader

      Case 3: unknown peer
        → check policy → check IP collision → broadcast MemberApproved
        → add to members → send Welcome → broadcast MemberSync
        → add to PeerTable → spawn_peer_reader
    }
```

### Joiner startup (`pitopi join`)

```
join_network_inner("gentle-amber-fox")
  → dht::resolve_directory("gentle-amber-fox")
      → (network_pkarr_pubkey, membership_dht_pubkey)
         ↓
  tokio::join!(                            parallel resolution
    dht::resolve_seed_list(network_pkarr_pubkey),
    dht::resolve_membership_hash(membership_dht_pubkey),
  )
      → (seed_peers, blake3_hash)
         ↓
  for each seed_peer in seed_peers:        fetch membership blob
    try_fetch_blob_from_peer(seed_peer, hash)
      → verify hash → deserialize MembershipData
         ↓
  loop {                                   outer reconnect loop
    conn = connect_to_peer(coordinator_or_any_member)
         ↓
    enter_mesh(conn, ...)
      → tun::create(my_ip)                (TunReader, TunWriter)
      → spawn_tun_writer(TunWriter)
      → spawn_reconnect_loop(...)          per-peer auto-reconnect
      → spawn_seed_list_publisher(...)     publish self as online peer
      → spawn_membership_poller(...)       check hash every 60s
      → join_mesh_shared(conn, ...)
      │   ↓
      │   recv Welcome { members, approved, dht_ids }
      │   → config::save()                persist membership + DHT pubkeys
      │   → peers.add(coordinator)        add to routing table
      │   → spawn_peer_reader(coordinator_conn)
      │   → for each other member:
      │       connect → send MeshHello → peers.add → spawn_peer_reader
      │   → spawn control_listener        listens for MemberApproved/MemberSync
      │   → spawn mesh_acceptor           accepts MeshHello from new peers
      │
      → forward::run_mesh(TunReader)       blocks here, forwarding packets
  }
```

### Data plane (steady state)

```
Outgoing packet (app → peer):

  App writes to 100.64.x.x
    → kernel routes to TUN (/10 netmask captures all 100.64-100.127)
    → TunReader.read_packet()              [run_mesh]
    → dest_ip(packet)                      extract IPv4 header bytes 16-19
    → PeerTable.lookup(dst_ip)             → Connection
    → conn.send_datagram(packet)           QUIC unreliable datagram

Incoming packet (peer → app):

  conn.read_datagram()                     [spawn_peer_reader, one per peer]
    → tun_tx.send(packet)                  mpsc channel
    → TunWriter.write_packet()             [spawn_tun_writer, single instance]
    → kernel delivers to app via TUN
```

### Per-peer reconnection

```
spawn_peer_reader detects conn.read_datagram() error
  → disconnect_tx.send(DisconnectEvent { endpoint_id, ip })
     ↓
  Coordinator (spawn_peer_cleanup):
    → peers.remove(ip)
    → done (peer reconnects to us)

  Joiner (spawn_reconnect_loop):
    → peers.remove(ip)
    → spawn per-peer reconnect task:
        loop {
          sleep(backoff)                   1s → 2s → 4s → ... → 30s cap
          connect_to_peer(endpoint_id)
          send MeshHello { identity, ip }
          peers.add(ip, new_conn)          transparently replaces old entry
          spawn_peer_reader(new_conn)      feeds back into disconnect_tx
          return
        }

  During gap:
    run_mesh does peers.lookup(ip) → None → packet silently dropped
  After reconnect:
    peers.lookup(ip) → new Connection → traffic resumes
```

### Task topology (per session)

```
┌─────────────────────────────────────────────────────────────┐
│ Main thread                                                  │
│  cmd_create / cmd_join / cmd_up                              │
│    → run_accept_loop (coord) or run_mesh (joiner)            │
└─────────────────────────────────────────────────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐
│ spawn_tun_writer │  │ spawn_peer_reader│  │ spawn_peer_    │
│ (1 per session)  │  │ (1 per peer)     │  │ reader (peer B)│
│                  │  │                  │  │                │
│ tun_rx → TUN     │  │ conn → tun_tx    │  │ conn → tun_tx  │
└──────────────────┘  └──────────────────┘  └────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐
│ spawn_path_      │  │ spawn_dht_       │  │ spawn_peer_    │
│ logger           │  │ publisher        │  │ cleanup /      │
│ (1 per peer)     │  │ (coord only)     │  │ reconnect_loop │
└──────────────────┘  └──────────────────┘  └────────────────┘

┌──────────────────┐  ┌──────────────────┐
│ spawn_seed_list_ │  │ spawn_membership_│
│ publisher        │  │ poller           │
│ (all peers)      │  │ (all peers)      │
│ every 300s       │  │ every 60s        │
└──────────────────┘  └──────────────────┘

┌──────────────────┐  ┌──────────────────┐
│ control_listener │  │ mesh_acceptor    │
│ (joiner only)    │  │ (joiner only)    │
│ MemberApproved,  │  │ MeshHello,       │
│ MemberSync       │  │ ReconnectRequest │
└──────────────────┘  └──────────────────┘
```

---

## 20. Security Model

### Transport security

All communication is encrypted end-to-end by iroh's QUIC implementation. Connections use TLS 1.3 with Ed25519 certificates derived from each peer's keypair. No traffic -- including relayed traffic -- can be read or modified by intermediaries.

### Identity authentication

Peers authenticate at two levels:

1. **Transport level:** The QUIC handshake verifies each peer's Ed25519 public key. A peer's `EndpointId` is cryptographically bound to their connection. You cannot connect to a peer without them proving they hold the corresponding private key.

2. **Application level:** When peers send `MeshHello` or `ReconnectRequest` messages, pitopi verifies that the claimed identity matches the transport-level identity (`conn.remote_id()`). This prevents a connected peer from claiming to be someone else.

### Membership authorization

Pitopi separates *authorization* (who can approve a new identity) from *welcome* (who can let an approved peer into the mesh):

- **Restricted mode:** Only the coordinator can authorize new members. However, once a peer is approved and the `MemberApproved` message is broadcast, *any* peer can welcome that approved identity when it connects. This means the coordinator doesn't need to be online when the approved peer actually joins -- it just needs to have been online long enough to broadcast the approval.

- **Open mode:** Any member can both authorize and welcome new peers. No coordinator involvement needed at all.

Unknown peers (not in either the member list or the approved list) are always rejected by the mesh acceptor. A peer must be explicitly approved before any node will let it in.

### IP address integrity

Virtual IPs are derived from cryptographic identities, not assigned by the coordinator. Both the coordinator and the joiner verify the derivation:

1. The coordinator checks for IP collisions against the member list and approved list before broadcasting `MemberApproved`.
2. The joiner checks its own derived IP against the member list received in the `Welcome` message.

No peer can assign a different IP than what the identity hash produces. This means a peer's IP is a stable, verifiable identifier.

### DHT record integrity

Pitopi uses four pkarr record types with different trust levels:

- **Directory records** map the network name to DHT public keys. They are keyed by a deterministic hash of the network name (no secret required to look up, but no secret to forge either — the record is informational).
- **Seed list records** are signed by `network_pkarr_pubkey`, derived from `network_secret`. Only peers in possession of the membership blob (which contains `network_secret`) can publish or update seed lists.
- **Membership records** are signed by `membership_signing_key`, derived from the coordinator's private secret key. Only the coordinator can publish membership updates. The pkarr relay verifies signatures, and peers verify the blake3 hash of the membership blob before trusting its contents.
- **ACL records** are signed by `acl_signing_key`, derived from the coordinator's private secret key + network name. Only the coordinator can publish ACL updates. Peers verify the blake3 hash of the ACL blob before applying it.

A rogue peer outside the network cannot forge any of these records without either the coordinator's private key (for membership) or the `network_secret` from the membership blob (for seed lists).

### What is NOT protected

- **Traffic analysis:** An observer on the network can see that two peers are communicating (via packet timing and size), even though they can't read the content.
- **Denial of service:** A peer can flood the network with packets. No rate limiting is currently implemented.
- **Member list confidentiality:** The member list (identities and IPs) is shared with all members. A member can see who else is in the network.
- **Reconnection window:** Packets to a disconnected peer are silently dropped until the reconnect loop establishes a new connection (up to 30 seconds with backoff).
