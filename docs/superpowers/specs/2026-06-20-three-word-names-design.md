# Three-Word Network Names

## Context

Network names are currently user-chosen strings (e.g., `gaming`) used as the network ID for ALPNs, config keys, and room codes. This creates a collision problem: a user in two networks with the same name would have conflicting ALPNs and config entries. Additionally, room codes encode the coordinator's endpoint ID in z-base-32, which is long and unfriendly.

This design replaces user-chosen names with auto-generated three-word names (like Docker container names). The name becomes the network's unique identifier and the only thing a joiner needs to know.

## Design

### Name Generation

Three embedded word lists of ~1024 words each: adjectives, nouns-A, nouns-B. At creation, one word is picked randomly from each list, producing names like `gentle-amber-fox`. The name is checked against the directory pkarr record — if already taken, retry with new words.

Format: `adjective-noun-noun` (e.g., `bright-copper-moon`, `calm-silver-wave`).

New module: `src/network_name.rs` — word lists, generation, validation.

### DHT Records (Three-Step Lookup)

Three pkarr records per network, each serving a distinct purpose:

**1. Directory record** — maps name to network identity:
- Signing key: `blake3::derive_key("pitopi/directory", name_bytes)` → Ed25519 keypair
- Value: DNS TXT records containing the network pkarr public key and the membership DHT public key (both hex-encoded)
- Published once at creation by the coordinator, re-published periodically
- The signing key is derivable from the name, so technically anyone who knows the name can overwrite it. This is a known limitation addressed by the future rendezvous server.

**2. Seed list record** — maps network secret to online peers:
- Signing key: random 32-byte network secret, generated at creation
- Value: DNS TXT records containing endpoint IDs of currently-online peers
- Only publishable by holders of the network secret (coordinator and members via the blob)
- Refreshed when peers join, leave, or disconnect

**3. Membership record** — maps coordinator identity to membership hash:
- Signing key: `blake3::derive_key("pitopi/membership/<name>", coordinator_secret_key_bytes)` (existing derivation, updated to use three-word name)
- Value: DNS TXT record containing the blake3 hash of the membership blob
- Published by the coordinator on membership changes

### Membership Blob

The canonical msgpack blob gains new fields:

```
{
  members: [{ identity, ip, is_coordinator }],
  approved: [{ identity, ip }],
  network_secret: [u8; 32],
  membership_signing_key: [u8; 32]
}
```

- `network_secret`: the signing private key for the seed list record. Distributed to all members via the blob so any member can verify the seed list. Only the coordinator publishes the seed list for now; multi-admin publishing is a future feature.
- `membership_signing_key`: the signing private key for the membership record. In the blob so future multi-admin support can allow any admin to publish membership changes. For now, only the coordinator uses it.

### Join Flow

1. User runs `pitopi join gentle-amber-fox`
2. Derive directory pkarr key from name → resolve → get network pkarr public key + membership DHT public key
3. In parallel:
   - Resolve seed list record (using network pkarr public key) → get peer endpoint IDs
   - Resolve membership record (using membership DHT public key) → get blob hash
4. Connect to any listed peer via iroh-blobs ALPN
5. Fetch membership blob by hash, verify blake3 hash matches
6. Deserialize blob → get member list, network secret, check own identity is in approved list
7. Connect to mesh peers via network ALPN (`pitopi/net/gentle-amber-fox`)

### Membership Polling & Reconciliation

Every peer periodically checks the membership DHT record for hash changes (every 60 seconds):

1. Resolve membership record → compare hash to local
2. If changed, fetch new blob from any peer via iroh-blobs
3. Compare old vs new member/approved lists:
   - **New members appeared** — accept incoming connections from them
   - **Members removed** — close connections, remove from PeerTable
   - **Self removed** — disconnect from everything, notify user

This allows kicks and membership changes to propagate without the coordinator being connected to every peer.

### Admin Operations

Single coordinator model (multi-admin is a future feature):

- **Add member**: coordinator updates approved list in blob, publishes new hash
- **Kick member**: coordinator removes from member/approved lists, rotates network secret, publishes new hash + new seed list under new key, updates directory to point to new network pkarr public key
- **Transfer ownership**: coordinator promotes another member to coordinator (`is_coordinator: true`), demotes self, updates blob
- **Nuke room**: if other members exist, prompt to transfer coordinator role first. If forced or no other members, publish empty blob and clear seed list.

### Secret Rotation on Kick

When a member is kicked:

1. Coordinator generates new network secret (new 32-byte random key)
2. Updates blob: remove kicked member, set new network secret
3. Publishes membership record with new blob hash
4. Publishes seed list under new network secret (new pkarr key)
5. Updates directory record to point to new network pkarr public key
6. Old seed list record (under old secret) becomes abandoned — kicked user can only publish there, which nobody looks at

### CLI Changes

- `pitopi create` — no `--name` flag. Auto-generates three-word name, prints it. Keeps `--mode` flag.
- `pitopi join <name>` — argument is the three-word name. No `--name` flag, no endpoint ID needed.
- `pitopi leave <name>` — three-word name.
- `pitopi status` — shows networks by three-word names.
- `pitopi nuke <name>` — new command. Transfers coordinator role or destroys room.
- `pitopi promote <name> <peer>` — future, for multi-admin.

### Config Changes

`networks.toml` uses three-word names as keys. `NetworkConfig` changes:
- Remove `coordinator_id` field (it's in the blob's member list)
- Add `network_pkarr_pubkey: Option<String>` (hex, for resolving seed list)
- Add `membership_dht_pubkey: Option<String>` (hex, for resolving membership hash)

### ALPN Changes

Format stays the same, just uses generated names: `pitopi/net/gentle-amber-fox`.

### What Gets Removed

- `src/room_code.rs` — the three-word name replaces room codes
- `--name` flag on create/join CLI commands
- Room code generation/parsing in daemon
- `room_code` field on `NetworkHandle`
- `coordinator_id` from `NetworkConfig` (redundant with blob data)

## Verification

1. `cargo -q check` — compiles
2. `cargo -q test` — all tests pass
3. `cargo -q clippy` — no warnings
4. Manual: create network (get three-word name), join from another peer using just the name, verify mesh works, test kick + secret rotation, test nuke + transfer
