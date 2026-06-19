# Phase 1: Harden the Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the two-peer VPN rock-solid — clean shutdown, reconnection, stats, and privilege checks.

**Architecture:** A `CancellationToken` threads through all async tasks as the shared shutdown signal. Stats use lock-free atomics. The reconnect loop wraps connect+forward, keeping the TUN device alive across reconnections. Root check gates startup.

**Tech Stack:** Rust, tokio, iroh, tun crate, tokio-util (CancellationToken), libc (euid check)

## Global Constraints

- Use `cargo -q` for all cargo commands
- Use `tracing` for logging (INFO level)
- TUN MTU: 1200 bytes — all packets fit in QUIC datagrams, no stream fallback needed
- Must compile on both macOS (aarch64-apple-darwin) and Linux (x86_64-unknown-linux-gnu)
- No `unwrap()` or `panic!()` — use `anyhow::Result` with `.context()` for errors
- Existing tests: none. This plan adds unit tests for testable pure logic (stats, backoff). Integration tests require sudo + TUN and are out of scope.

---

### Task 1: Add dependencies and root privilege check

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs`

**Interfaces:**
- Produces: `check_root()` — called at top of `main()`, exits with code 1 if not root

- [ ] **Step 1: Add `tokio-util` and `libc` to Cargo.toml**

Add to `[dependencies]` in `Cargo.toml`:

```toml
libc = "0.2"
tokio-util = "0.7"
```

- [ ] **Step 2: Add root check function and call it in main()**

Add to `src/main.rs`, before the existing `cmd_create` function:

```rust
fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("pitopi requires root privileges to create TUN devices. Run with sudo.");
        std::process::exit(1);
    }
}
```

Call it as the first line inside `main()`, before tracing init:

```rust
async fn main() -> Result<()> {
    check_root();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    // ... rest unchanged
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo -q check`
Expected: compiles with no errors

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs
git commit -m "Add root privilege check and new dependencies"
```

---

### Task 2: Shutdown signal handling

**Files:**
- Create: `src/shutdown.rs`
- Modify: `src/main.rs` (add `mod shutdown;`)

**Interfaces:**
- Produces: `shutdown::token() -> CancellationToken` — creates the token and spawns the signal listener task. Returns the token for cloning into other tasks.

- [ ] **Step 1: Write the shutdown module**

Create `src/shutdown.rs`:

```rust
use tokio_util::sync::CancellationToken;

pub fn token() -> CancellationToken {
    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        signal_listener().await;
        tracing::info!("shutdown signal received");
        t.cancel();
    });
    token
}

async fn signal_listener() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}
```

- [ ] **Step 2: Register the module in main.rs**

Add `mod shutdown;` to the module declarations at the top of `src/main.rs`:

```rust
mod forward;
mod identity;
mod shutdown;
mod transport;
mod tun;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo -q check`
Expected: compiles with no errors (shutdown module is created but not yet used)

- [ ] **Step 4: Commit**

```bash
git add src/shutdown.rs src/main.rs
git commit -m "Add shutdown signal handler module"
```

---

### Task 3: Stats collection

**Files:**
- Create: `src/stats.rs`
- Modify: `src/main.rs` (add `mod stats;`)

**Interfaces:**
- Produces:
  - `Stats::new() -> Arc<Stats>` — creates a new stats tracker
  - `Stats::record_rx(&self, bytes: usize)` — called by forwarding loop on each received packet
  - `Stats::record_tx(&self, bytes: usize)` — called by forwarding loop on each sent packet
  - `Stats::record_drop(&self)` — called on send failures
  - `Stats::spawn_logger(&self, token: CancellationToken)` — spawns background task that logs every 30s and prints final summary on shutdown
- Consumes: `CancellationToken` from `shutdown::token()`

- [ ] **Step 1: Write the stats module with tests**

Create `src/stats.rs`:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio_util::sync::CancellationToken;

pub struct Stats {
    packets_rx: AtomicU64,
    packets_tx: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    drops: AtomicU64,
    start_time: Instant,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            packets_rx: AtomicU64::new(0),
            packets_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            drops: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }

    pub fn record_rx(&self, bytes: usize) {
        self.packets_rx.fetch_add(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_tx(&self, bytes: usize) {
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
        self.bytes_tx.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn spawn_logger(self: &Arc<Self>, token: CancellationToken) {
        let stats = self.clone();
        tokio::spawn(async move {
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            let mut prev_bytes_rx = 0u64;
            let mut prev_bytes_tx = 0u64;

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        let rx = stats.packets_rx.load(Ordering::Relaxed);
                        let tx = stats.packets_tx.load(Ordering::Relaxed);
                        let brx = stats.bytes_rx.load(Ordering::Relaxed);
                        let btx = stats.bytes_tx.load(Ordering::Relaxed);
                        let drops = stats.drops.load(Ordering::Relaxed);

                        tracing::info!(
                            rx = rx - prev_rx,
                            tx = tx - prev_tx,
                            bytes_rx = format_bytes(brx - prev_bytes_rx),
                            bytes_tx = format_bytes(btx - prev_bytes_tx),
                            drops,
                            "(30s)"
                        );

                        prev_rx = rx;
                        prev_tx = tx;
                        prev_bytes_rx = brx;
                        prev_bytes_tx = btx;
                    }
                    _ = token.cancelled() => {
                        stats.log_summary();
                        return;
                    }
                }
            }
        });
    }

    fn log_summary(&self) {
        let duration = self.start_time.elapsed();
        let mins = duration.as_secs() / 60;
        let secs = duration.as_secs() % 60;

        let total_bytes = self.bytes_rx.load(Ordering::Relaxed)
            + self.bytes_tx.load(Ordering::Relaxed);

        tracing::info!(
            duration = format!("{}m{}s", mins, secs),
            total_rx = self.packets_rx.load(Ordering::Relaxed),
            total_tx = self.packets_tx.load(Ordering::Relaxed),
            total_bytes = format_bytes(total_bytes),
            "session complete"
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_rx() {
        let stats = Stats::new();
        stats.record_rx(100);
        stats.record_rx(200);
        assert_eq!(stats.packets_rx.load(Ordering::Relaxed), 2);
        assert_eq!(stats.bytes_rx.load(Ordering::Relaxed), 300);
    }

    #[test]
    fn test_record_tx() {
        let stats = Stats::new();
        stats.record_tx(500);
        assert_eq!(stats.packets_tx.load(Ordering::Relaxed), 1);
        assert_eq!(stats.bytes_tx.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn test_record_drop() {
        let stats = Stats::new();
        stats.record_drop();
        stats.record_drop();
        assert_eq!(stats.drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(87244), "85.2KB");
        assert_eq!(format_bytes(1_153_434), "1.1MB");
    }
}
```

- [ ] **Step 2: Register the module in main.rs**

Add `mod stats;` to the module declarations in `src/main.rs`:

```rust
mod forward;
mod identity;
mod shutdown;
mod stats;
mod transport;
mod tun;
```

- [ ] **Step 3: Run tests**

Run: `cargo -q test`
Expected: all 4 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/stats.rs src/main.rs
git commit -m "Add stats collection with periodic logging"
```

---

### Task 4: Wire shutdown and stats into forwarding

**Files:**
- Modify: `src/forward.rs`

**Interfaces:**
- Consumes:
  - `CancellationToken` from `shutdown::token()`
  - `Arc<Stats>` from `Stats::new()`
- Produces: `forward::run(tun: TunDevice, conn: Connection, token: CancellationToken, stats: Arc<Stats>) -> Result<()>` — updated signature. Returns `Ok(())` on shutdown or connection close, `Err` on unexpected failure.

- [ ] **Step 1: Update forward::run signature and pass deps to loops**

Replace the entire contents of `src/forward.rs`:

```rust
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::Connection;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::stats::Stats;
use crate::tun::TunDevice;

pub async fn run(
    tun: TunDevice,
    conn: Connection,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(256);

    let tun_to_iroh = tokio::spawn(tun_read_loop(
        tun,
        conn.clone(),
        tun_rx,
        token.clone(),
        stats.clone(),
    ));
    let iroh_to_tun = tokio::spawn(iroh_read_loop(conn, tun_tx, token.clone(), stats));

    tokio::select! {
        r = tun_to_iroh => r??,
        r = iroh_to_tun => r??,
    }

    Ok(())
}

async fn tun_read_loop(
    mut tun: TunDevice,
    conn: Connection,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = tun.read_packet(&mut buf) => {
                let n = result?;
                if n > 0 {
                    match conn.send_datagram(Bytes::copy_from_slice(&buf[..n])) {
                        Ok(()) => stats.record_tx(n),
                        Err(_) => stats.record_drop(),
                    }
                }
            }
            Some(packet) = incoming.recv() => {
                tun.write_packet(&packet).await?;
            }
        }
    }
}

async fn iroh_read_loop(
    conn: Connection,
    tun_tx: mpsc::Sender<Vec<u8>>,
    token: CancellationToken,
    stats: Arc<Stats>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = conn.read_datagram() => {
                let datagram = result?;
                stats.record_rx(datagram.len());
                if tun_tx.send(datagram.to_vec()).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo -q check`
Expected: compile errors in `main.rs` because `forward::run` now requires extra args. This is expected — Task 5 will fix it.

- [ ] **Step 3: Commit**

```bash
git add src/forward.rs
git commit -m "Wire shutdown token and stats into forwarding loops"
```

---

### Task 5: Reconnect loop and main() restructure

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes:
  - `shutdown::token() -> CancellationToken`
  - `Stats::new() -> Arc<Stats>`
  - `Stats::spawn_logger(&self, token: CancellationToken)`
  - `forward::run(tun, conn, token, stats) -> Result<()>`

- [ ] **Step 1: Rewrite main.rs with reconnect loop**

Replace the entire contents of `src/main.rs`:

```rust
mod forward;
mod identity;
mod shutdown;
mod stats;
mod transport;
mod tun;

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::EndpointId;

const SELF_IP_CREATE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const PEER_IP_CREATE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

const BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_secs(1);
const BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "pitopi", about = "P2P mesh VPN powered by iroh")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new network and wait for peers
    Create,
    /// Join an existing network using a node ID
    Join {
        /// The endpoint ID of the network creator
        node_id: EndpointId,
    },
}

fn check_root() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("pitopi requires root privileges to create TUN devices. Run with sudo.");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    check_root();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    let cli = Cli::parse();

    let token = shutdown::token();
    let stats = stats::Stats::new();
    stats.spawn_logger(token.clone());

    match cli.command {
        Command::Create => cmd_create(token, stats).await,
        Command::Join { node_id } => cmd_join(node_id, token, stats).await,
    }
}

async fn cmd_create(
    token: tokio_util::sync::CancellationToken,
    stats: std::sync::Arc<stats::Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let ep = transport::create_endpoint(key).await?;

    tracing::info!("network created");
    tracing::info!(ip = %SELF_IP_CREATE, "your virtual IP");
    tracing::info!(node_id = %ep.id(), "share this node ID with your peer");

    let tun = tun::TunDevice::create(SELF_IP_CREATE, PEER_IP_CREATE)
        .context("failed to create TUN device")?;

    let mut backoff = BACKOFF_INITIAL;

    loop {
        tracing::info!("waiting for a peer to join...");

        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = transport::accept_connection(&ep) => {
                match result {
                    Ok(conn) => {
                        backoff = BACKOFF_INITIAL;
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept connection");
                        backoff_sleep(&token, &mut backoff).await;
                        continue;
                    }
                }
            }
        };

        tracing::info!("peer connected, tunnel active");

        if let Err(e) = forward::run(tun.share(), conn, token.clone(), stats.clone()).await {
            if token.is_cancelled() {
                return Ok(());
            }
            tracing::warn!(error = %e, "connection lost, reconnecting...");
            backoff_sleep(&token, &mut backoff).await;
        }
    }
}

async fn cmd_join(
    node_id: EndpointId,
    token: tokio_util::sync::CancellationToken,
    stats: std::sync::Arc<stats::Stats>,
) -> Result<()> {
    let key = identity::load_or_create()?;
    let ep = transport::create_endpoint(key).await?;

    let tun = tun::TunDevice::create(PEER_IP_CREATE, SELF_IP_CREATE)
        .context("failed to create TUN device")?;

    let mut backoff = BACKOFF_INITIAL;

    loop {
        tracing::info!("connecting to network...");

        let conn = tokio::select! {
            _ = token.cancelled() => return Ok(()),
            result = transport::connect_to_peer(&ep, node_id) => {
                match result {
                    Ok(conn) => {
                        backoff = BACKOFF_INITIAL;
                        conn
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to connect");
                        backoff_sleep(&token, &mut backoff).await;
                        continue;
                    }
                }
            }
        };

        tracing::info!(ip = %PEER_IP_CREATE, "connected, tunnel active");

        if let Err(e) = forward::run(tun.share(), conn, token.clone(), stats.clone()).await {
            if token.is_cancelled() {
                return Ok(());
            }
            tracing::warn!(error = %e, "connection lost, reconnecting...");
            backoff_sleep(&token, &mut backoff).await;
        }
    }
}

async fn backoff_sleep(
    token: &tokio_util::sync::CancellationToken,
    backoff: &mut std::time::Duration,
) {
    tracing::info!(secs = backoff.as_secs(), "retrying in");
    tokio::select! {
        _ = token.cancelled() => {}
        _ = tokio::time::sleep(*backoff) => {}
    }
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
}
```

- [ ] **Step 2: Add TunDevice::share() for reuse across reconnections**

The reconnect loop needs to pass the TUN device into `forward::run` multiple times. Since `TunDevice` wraps an `AsyncDevice` which isn't `Clone`, we need to share it. Add a `share()` method to `src/tun.rs` that returns a handle the forwarding loop can use.

Replace `src/tun.rs`:

```rust
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tun::{AsyncDevice, Configuration};

const TUN_MTU: u16 = 1200;

pub struct TunDevice {
    device: Arc<Mutex<AsyncDevice>>,
}

impl TunDevice {
    pub fn create(addr: Ipv4Addr, dest: Ipv4Addr) -> Result<Self> {
        let mut config = Configuration::default();
        config
            .address(addr)
            .destination(dest)
            .netmask((255, 255, 255, 0))
            .mtu(TUN_MTU)
            .up();

        #[cfg(target_os = "linux")]
        config.platform_config(|p| {
            p.ensure_root_privileges(true);
        });

        let device = tun::create_as_async(&config)?;
        tracing::info!(%addr, "TUN device created");
        Ok(Self {
            device: Arc::new(Mutex::new(device)),
        })
    }

    pub fn share(&self) -> TunDevice {
        TunDevice {
            device: self.device.clone(),
        }
    }

    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        let mut dev = self.device.lock().await;
        let n = dev.read(buf).await?;
        Ok(n)
    }

    pub async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let mut dev = self.device.lock().await;
        dev.write_all(packet).await?;
        Ok(())
    }
}
```

- [ ] **Step 3: Update forward.rs to use shared TunDevice**

In `src/forward.rs`, the `tun_read_loop` function takes `mut tun: TunDevice` — change it to `tun: TunDevice` (no `mut` needed since `read_packet`/`write_packet` now take `&self`):

In the function signature of `tun_read_loop`, change:
```rust
// Before:
async fn tun_read_loop(
    mut tun: TunDevice,
// After:
async fn tun_read_loop(
    tun: TunDevice,
```

- [ ] **Step 4: Verify it compiles and tests pass**

Run: `cargo -q check && cargo -q test`
Expected: compiles with no errors, all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/tun.rs src/forward.rs
git commit -m "Add reconnect loop with exponential backoff"
```

---

### Task 6: Update TODO.md

**Files:**
- Modify: `TODO.md`

- [ ] **Step 1: Mark completed Phase 1 items**

In `TODO.md`, check off completed items under Phase 1:

```markdown
## Phase 1: Harden the foundation

Make the two-peer case rock-solid before adding complexity.

- [x] Signal handling — catch SIGINT/SIGTERM, tear down TUN device and close iroh connection cleanly
- [x] Root/sudo check — detect missing privileges early with a clear error message instead of a cryptic TUN failure
- [x] Reconnect loop — if the iroh connection drops, retry with exponential backoff instead of exiting
- [ ] ~~Oversized packet handling~~ — not needed, TUN MTU of 1200 ensures packets fit in QUIC datagrams
- [x] Periodic stats logging — packets sent/received, bytes transferred, drops, latency estimate
- [x] Graceful shutdown — flush in-flight datagrams, log session summary on exit
- [ ] Cross-platform testing — verify macOS ↔ Linux, Linux ↔ Linux, macOS ↔ macOS
```

- [ ] **Step 2: Commit**

```bash
git add TODO.md
git commit -m "Update TODO.md with Phase 1 progress"
```
