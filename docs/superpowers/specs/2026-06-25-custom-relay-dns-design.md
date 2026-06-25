# Custom relay, discovery-DNS, and DNS-upstream configuration

Date: 2026-06-25
Status: design approved, pending spec review

## Goal

Let users optionally point rayfish at custom infrastructure, including the
rayfish-operated relay and DNS-discovery servers, instead of (or alongside)
iroh's n0 defaults. Defaults stay n0 — existing installs see no behavior change
until they opt in.

Deployed rayfish infra this targets:

- relay: `http://relay.iroh.rayfish.xyz:3340`
- discovery DNS: `http://dns.iroh.rayfish.xyz:8080`

## Scope

Three independent global settings:

1. `relay` — iroh transport relay (NAT-traversal fallback).
2. `discovery-dns` — iroh's DNS/pkarr discovery server (resolve + publish).
3. `dns-upstreams` — Magic DNS upstream forwarders for non-`.ray` queries.

All three are global by nature: there is one shared iroh `Endpoint` and one
Magic DNS resolver across every network, so per-network overrides do not apply.

Each setting is independent and supports an `augment` (default) or `replace`
mode. Each value is a comma list of **preset keywords** (`rayfish`, `n0`) or
literal URLs/IPs. Presets resolve at use time so a release can change a preset's
URL without rewriting user config.

Out of scope (YAGNI): per-network overrides; live re-bind of the endpoint for
relay/discovery changes (restart instead); a single bundled "provider" switch
(settings are independent); disabling relay entirely.

## iroh integration (authoritative)

The current `transport.rs::bind_endpoint()` uses the `presets::N0` convenience,
which bundles relay + discovery. To support custom servers we move to the
explicit builder form **only when an override is configured**; with no override,
the existing `presets::N0` path is preserved unchanged.

Reference shape (one discovery URL drives three mechanisms):

```rust
let dns_origin: Url = "http://dns.iroh.rayfish.xyz:8080".parse()?;
let relay: RelayMode = RelayMode::Custom("http://relay.iroh.rayfish.xyz:3340".parse()?);

let ep = Endpoint::builder()
    .secret_key(secret)
    .relay_mode(relay)
    .dns_resolver(DnsResolver::new(dns_origin.clone()))            // DNS resolve
    .discovery(PkarrResolver::new(dns_origin.clone()).into())     // pkarr resolve
    .discovery(iroh::discovery::pkarr::PkarrPublisher::new(dns_origin).into()) // pkarr publish
    .bind()
    .await?;
```

Mode semantics:

- `relay` replace: `RelayMode::Custom(<custom>)`. `relay` augment: build a
  `RelayMap` of n0's default relay nodes plus the custom node(s). (`RelayMode`
  has no built-in "default + custom"; the plan builds the combined map and
  confirms the exact iroh API against the installed version.)
- `discovery-dns` replace: register only the custom `DnsResolver` +
  `PkarrResolver` + `PkarrPublisher`. augment: also stack n0's default discovery
  (pkarr resolve/publish stack via repeated `.discovery(...)`; `.dns_resolver()`
  is singular, so under augment it is set to the custom origin while the n0
  discovery services remain stacked — the plan confirms this stacking behavior).
- The `dht.rs` `PkarrRelayClient` (currently `https://dns.iroh.link/pkarr`)
  must also follow `discovery-dns` so blob/contact publish+resolve use the same
  server. The plan confirms whether the one deployed DNS server covers both the
  endpoint-builder discovery and the `dht.rs` pkarr-relay path, or whether they
  need separate URLs.

`dns-upstreams` is unrelated to the endpoint. It is applied at the Magic DNS
resolver (`daemon.rs` `set_upstreams`, ~line 3065): final list =
`replace ? custom : custom + captured_upstreams()`. This is the only setting
that applies live (no restart).

## Config schema (`config.rs` → `settings.toml`)

New optional global settings on `AppConfig` / `Settings`. A small shared type:

```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerOverride {
    #[serde(default)]
    pub servers: Vec<String>, // preset keyword or literal URL/IP, as typed
    #[serde(default)]
    pub replace: bool,        // false = augment defaults (default)
}
```

Serialized form:

```toml
[relay]
servers = ["rayfish"]
replace = false

[discovery_dns]
servers = ["rayfish"]
replace = false

[dns_upstreams]
servers = ["1.1.1.1", "8.8.8.8"]
replace = false
```

An omitted or empty `servers` list = unset = today's behavior exactly. `serde`
defaults ensure pre-existing `settings.toml` files load as "unset". Persisted
via the existing `config::save_settings()` atomic write path.

Preset table (constants in the resolving modules):

- `relay`: `rayfish` → `http://relay.iroh.rayfish.xyz:3340`, `n0` → iroh default.
- `discovery-dns`: `rayfish` → `http://dns.iroh.rayfish.xyz:8080`, `n0` → iroh default.
- `dns-upstreams`: no presets; literal IPs only.

## CLI surface (`main.rs`)

```
ray config                      # list all settings (alias: ray config get)
ray config get <key>            # one key
ray config set <key> <value> [--replace]   # value = comma list
ray config unset <key>          # revert key to default
```

- Keys: `relay`, `discovery-dns`, `dns-upstreams`.
- Default mode is **augment**; `--replace` opts into replacement. `--replace`
  help text notes the connectivity risk (a bad custom server with no fallback
  can isolate the node).
- Validation: `relay` / `discovery-dns` entries must be a known preset keyword
  or an `http`/`https` URL (`Url::parse`, scheme check); `dns-upstreams`
  entries must be an IP or `IP:port`; unknown preset keywords rejected.
- Setting `relay` or `discovery-dns` prints `run 'sudo ray restart' to apply`.
  Setting `dns-upstreams` applies live and says so.
- `--json` honored for `get` (machine-readable key/value list).

Short aliases follow existing conventions (`get`→`ls`/`show` where it fits,
`unset`→`rm`); finalized in the plan to stay unique within the subcommand enum.

## IPC (`ipc.rs`) + privilege

The daemon owns `/etc/rayfish` and is root, so `set`/`unset` go over IPC like
other mutating commands (operator model). New messages:

- `ConfigGet { key: Option<String> }` → `ConfigValues(Vec<(String, String)>)`.
  Read; open to any local user (matches `status`/`show`).
- `ConfigSet { key: String, value: String, replace: bool }` →
  `ConfigResult { needs_restart: bool }` / error. Mutating; requires
  root/operator via `check_authorized()`.
- `ConfigUnset { key: String }` → same response.

Daemon handlers: parse + validate the key/value, update the in-memory
`AppConfig`, persist via `save_settings()`, then: for `dns-upstreams`,
re-resolve and call `set_upstreams` live (`needs_restart = false`); for
`relay` / `discovery-dns`, set `needs_restart = true` and apply on next bind.

## Resolution module

A focused resolver (new `src/serverconfig.rs` or a section of `config.rs`) turns
a `ServerOverride` into concrete iroh inputs, with one function per target:

- `resolve_relay(&ServerOverride) -> RelayMode` (Custom or combined RelayMap).
- `resolve_discovery(&ServerOverride) -> Vec<Url>` + builder wiring helper.
- `resolve_upstreams(&ServerOverride, captured: &[..]) -> Vec<SocketAddr>`.

Keeps preset→URL mapping, mode logic, and validation in one testable place;
`transport.rs` / `dht.rs` / `daemon.rs` call it at their bind/apply points.

## Testing

Unit:

- Preset resolution (`rayfish`/`n0`/unknown) for relay and discovery-dns.
- Entry parsing/validation: good and bad URLs, good and bad IPs, `IP:port`,
  unknown preset rejected.
- Mode list-building for all three (augment vs replace), including dns-upstreams
  augment merging with a sample captured list.
- `settings.toml` round-trip with serde defaults: an old file (no new sections)
  loads as fully unset.

Manual:

- `ray config set dns-upstreams 1.1.1.1` then resolve a non-`.ray` name live.
- `ray config set relay rayfish` + `sudo ray restart`, confirm the endpoint
  binds against the rayfish relay; `ray config set discovery-dns rayfish` +
  restart, confirm publish/resolve via `dns.iroh.rayfish.xyz`.
- `ray config unset relay` restores n0.

## Risks / open items for the plan

1. Exact iroh API to combine n0 default relay nodes with a custom relay for the
   `relay` augment mode (vs. plain `RelayMode::Custom` for replace).
2. Whether one `discovery-dns` URL covers both the endpoint-builder discovery
   and the `dht.rs` pkarr-relay client, or they need distinct URLs.
3. Augment stacking semantics for `.dns_resolver()` (singular) vs `.discovery()`
   (stackable) — confirm the combined behavior matches "fall back to n0".
4. Restructuring `bind_endpoint()` to keep the `presets::N0` fast path when no
   override is set, switching to the explicit builder only when one is.
