//! Embedded mesh SSH server (`ray firewall ssh on`), Tailscale-style.
//!
//! The daemon runs a small SSH server bound to each of this node's mesh IPs on
//! port 22. A stock `ssh` client connecting to `<peer>.ray` (or the mesh IP)
//! lands here. There are no SSH keys: the connecting peer is already
//! cryptographically identified by the QUIC mesh link, and the kernel TCP stack
//! delivers the connection with the peer's mesh IP as the socket source (the
//! ingress anti-spoof check in [`crate::forward`] guarantees that IP is really
//! the peer's). We map that IP back to the peer identity via [`PeerTable`] and
//! admit the session iff the peer is in a shared network's `ssh_allow` list.
//!
//! Authorization is the only gate; SSH auth itself is the `none` method (the
//! identity is already proven). For now an authorized peer may log in as any
//! local unix user, including root — tighter user-mapping is future work.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use iroh::EndpointId;
use russh::keys::PrivateKey;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use smol_str::SmolStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::peers::{DeviceUserMap, PeerTable};

/// The port a stock `ssh` client targets (`ssh user@host.ray`). We can't bind it
/// directly: when a host sshd already holds `0.0.0.0:22`, the kernel rejects a
/// more-specific `<mesh-ip>:22` bind over the wildcard listener (EADDRINUSE,
/// regardless of SO_REUSEADDR/REUSEPORT). So the daemon binds [`SSH_LISTEN_PORT`]
/// and rewrites mesh `:22` <-> that port in its own forwarding path
/// ([`crate::forward`]), entirely in userspace — portable across Linux/macOS/
/// Windows, no OS firewall rules. The host sshd keeps `:22` on every other
/// interface untouched.
pub const SSH_PORT: u16 = 22;

/// Internal port the embedded SSH server binds (all platforms). Mesh `:22` is
/// translated to/from this port by the userspace NAT in `forward.rs`. Distinct
/// from the iroh listen port (41383).
pub const SSH_LISTEN_PORT: u16 = 41384;

/// Per-network SSH authorization snapshot: network name -> allow list, where
/// each entry is a peer's user-identity (hex [`EndpointId`]) or `"*"` (any peer
/// on that network). Held in an [`ArcSwap`] so `ray firewall ssh allow/deny`
/// updates are picked up by a live listener without a restart.
pub type SshAuthz = Arc<ArcSwap<HashMap<String, Vec<String>>>>;

/// Build an empty authorization snapshot.
pub fn new_authz() -> SshAuthz {
    Arc::new(ArcSwap::from_pointee(HashMap::new()))
}

/// Decide whether `user` (a peer's user identity) may open an SSH session, given
/// the networks we currently share with it. Authorized iff some shared network's
/// allow list contains the peer's identity or `"*"`.
fn is_authorized(authz: &SshAuthz, user: &EndpointId, networks: &[SmolStr]) -> bool {
    let map = authz.load();
    let id = user.to_string();
    networks.iter().any(|net| {
        map.get(net.as_str())
            .is_some_and(|list| list.iter().any(|e| e == "*" || e == &id))
    })
}

/// Handle to a running SSH server so the daemon can stop it on `ray down` /
/// `ssh off`. Dropping or cancelling the token tears down every listener.
pub struct SshServer {
    peers: PeerTable,
    device_user_map: DeviceUserMap,
    authz: SshAuthz,
}

impl SshServer {
    pub fn new(peers: PeerTable, device_user_map: DeviceUserMap, authz: SshAuthz) -> Self {
        Self {
            peers,
            device_user_map,
            authz,
        }
    }

    /// Spawn a listener on each mesh address (at [`SSH_LISTEN_PORT`]). Runs until
    /// `token` is cancelled. Mesh `:22` is mapped to this port by the userspace
    /// NAT in `forward.rs`, so a stock client connects on `:22` while the host
    /// sshd keeps `:22` on every other interface.
    pub fn spawn(self, addrs: Vec<IpAddr>, token: CancellationToken) {
        tokio::spawn(async move {
            let key = match load_or_generate_host_key() {
                Ok(k) => k,
                Err(e) => {
                    warn!(error = %e, "mesh SSH: could not load host key; SSH disabled");
                    return;
                }
            };
            let config = Arc::new(russh::server::Config {
                keys: vec![key],
                // Identity is proven by the mesh link, so the `none` method is
                // the only one offered; our `auth_none` is the authorization gate.
                methods: MethodSet::from(&[MethodKind::None][..]),
                inactivity_timeout: Some(Duration::from_secs(3600)),
                auth_rejection_time: Duration::from_secs(1),
                ..Default::default()
            });
            for addr in addrs {
                let listener = match bind_listener(addr, SSH_LISTEN_PORT) {
                    Ok(l) => l,
                    Err(e) => {
                        warn!(%addr, port = SSH_LISTEN_PORT, error = %e, "mesh SSH: cannot bind listener; skipping");
                        continue;
                    }
                };
                info!(%addr, port = SSH_LISTEN_PORT, "mesh SSH listening (reachable as :22)");
                let peers = self.peers.clone();
                let dum = self.device_user_map.clone();
                let authz = self.authz.clone();
                let config = config.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = token.cancelled() => break,
                            accepted = listener.accept() => {
                                let (stream, peer) = match accepted {
                                    Ok(p) => p,
                                    Err(e) => { debug!(error = %e, "mesh SSH accept failed"); continue; }
                                };
                                let config = config.clone();
                                let peers = peers.clone();
                                let dum = dum.clone();
                                let authz = authz.clone();
                                tokio::spawn(async move {
                                    handle_conn(stream, peer, config, peers, dum, authz).await;
                                });
                            }
                        }
                    }
                    debug!(%addr, "mesh SSH listener stopped");
                });
            }
        });
    }
}

/// Bind a TCP listener on a specific mesh IP's port 22 with SO_REUSEADDR (and
/// SO_REUSEPORT on Unix) so it can coexist with a host sshd bound on the wildcard
/// address. Returns a tokio listener ready to accept.
fn bind_listener(ip: IpAddr, port: u16) -> Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if ip.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = (ip, port).into();
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    let std_listener: std::net::TcpListener = sock.into();
    Ok(tokio::net::TcpListener::from_std(std_listener)?)
}

/// Resolve the connecting peer, decide authorization, and run the SSH session.
async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Arc<russh::server::Config>,
    peers: PeerTable,
    device_user_map: DeviceUserMap,
    authz: SshAuthz,
) {
    let src = peer.ip();
    let Some((peer_id, networks)) = peers.identity_and_networks(src) else {
        debug!(%src, "mesh SSH: connection from unknown mesh IP, dropping");
        return;
    };
    let user_identity = device_user_map.resolve(&peer_id);
    let authorized = is_authorized(&authz, &user_identity, &networks);
    debug!(%src, peer = %user_identity.fmt_short(), authorized, "mesh SSH connection");
    let handler = SshHandler::new(authorized, user_identity);
    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            let _ = session.await;
        }
        Err(e) => debug!(error = %e, "mesh SSH session ended with error"),
    }
}

/// A requested pseudo-terminal's initial geometry and terminal type.
struct PtyReq {
    term: String,
    col: u16,
    row: u16,
}

/// Per-connection SSH handler. Authorization is precomputed from the peer
/// identity before the handshake; `auth_none` just returns it.
struct SshHandler {
    authorized: bool,
    /// The connecting peer's user identity (for logging).
    user: EndpointId,
    /// The unix user the client asked to log in as (the `user` in `user@host`).
    login_user: String,
    pty: Option<PtyReq>,
    channel: Option<Channel<Msg>>,
    /// Set once a shell/exec session starts; forwards window-resize events to
    /// the task that owns the PTY.
    resize_tx: Option<mpsc::UnboundedSender<pty_process::Size>>,
}

impl SshHandler {
    fn new(authorized: bool, user: EndpointId) -> Self {
        Self {
            authorized,
            user,
            login_user: String::new(),
            pty: None,
            channel: None,
            resize_tx: None,
        }
    }

    /// Take the opened session channel and spawn the login shell (or `exec`
    /// command) on a fresh PTY, wiring it to the channel. Returns immediately so
    /// the russh session task stays free to process further requests (resize, …).
    fn start(&mut self, command: Option<String>, session: &mut Session) {
        let Some(channel) = self.channel.take() else {
            return;
        };
        let channel_id = channel.id();
        let handle = session.handle();
        let login_user = self.login_user.clone();
        let pty = self.pty.take();
        let peer = self.user;
        let (resize_tx, resize_rx) = mpsc::unbounded_channel();
        self.resize_tx = Some(resize_tx);

        tokio::spawn(async move {
            let code = match run_pty_session(channel, &login_user, command, pty, resize_rx).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(peer = %peer.fmt_short(), user = %login_user, error = %e, "mesh SSH session failed");
                    1
                }
            };
            let _ = handle.exit_status_request(channel_id, code).await;
            let _ = handle.eof(channel_id).await;
            let _ = handle.close(channel_id).await;
        });
    }
}

impl Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.login_user = user.to_string();
        if self.authorized {
            Ok(Auth::Accept)
        } else {
            info!(peer = %self.user.fmt_short(), "mesh SSH: rejecting unauthorized peer");
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channel = Some(channel);
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty = Some(PtyReq {
            term: term.to_string(),
            col: col_width as u16,
            row: row_height as u16,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(None, session);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        self.start(Some(cmd), session);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = &self.resize_tx {
            let _ = tx.send(pty_process::Size::new(row_height as u16, col_width as u16));
        }
        session.channel_success(channel)?;
        Ok(())
    }
}

/// Allocate a PTY, spawn the login shell (or `exec` command) as the requested
/// unix user, and pump bytes between the SSH channel and the PTY until the child
/// exits. Returns the child's exit code.
async fn run_pty_session(
    channel: Channel<Msg>,
    login_user: &str,
    command: Option<String>,
    pty_req: Option<PtyReq>,
    mut resize_rx: mpsc::UnboundedReceiver<pty_process::Size>,
) -> Result<u32> {
    use uzers::os::unix::UserExt;

    let pw = uzers::get_user_by_name(login_user)
        .with_context(|| format!("no such local user: {login_user}"))?;
    let uid = pw.uid();
    let gid = pw.primary_group_id();
    let home = pw.home_dir().to_path_buf();
    let shell = pw.shell().to_path_buf();
    let user_name = pw.name().to_string_lossy().to_string();

    let (pty, pts) = pty_process::open().context("opening pty")?;
    if let Some(p) = &pty_req {
        let _ = pty.resize(pty_process::Size::new(p.row, p.col));
    }

    let mut cmd = pty_process::Command::new(&shell);
    match &command {
        // `exec`: run the command through the login shell.
        Some(c) => {
            cmd = cmd.arg("-c").arg(c);
        }
        // Interactive: a login shell.
        None => {
            cmd = cmd.arg("-l");
        }
    }
    cmd = cmd
        .uid(uid)
        .gid(gid)
        .current_dir(&home)
        .env_clear()
        .env("HOME", &home)
        .env("USER", &user_name)
        .env("LOGNAME", &user_name)
        .env("SHELL", &shell)
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
    if let Some(p) = &pty_req {
        cmd = cmd.env("TERM", &p.term);
    }
    let mut child = cmd.spawn(pts).context("spawning login shell")?;

    let stream = channel.into_stream();
    let (mut chan_read, mut chan_write) = tokio::io::split(stream);
    let (mut pty_read, mut pty_write) = pty.into_split();

    // Client -> PTY, interleaved with window resizes (both touch the write half).
    let c2p = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            tokio::select! {
                r = chan_read.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if pty_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                },
                Some(size) = resize_rx.recv() => {
                    let _ = pty_write.resize(size);
                }
            }
        }
    });

    // PTY -> client. Ends when the child exits and the master side EOFs.
    let p2c = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut pty_read, &mut chan_write).await;
        let _ = chan_write.shutdown().await;
    });

    let status = child.wait().await.context("waiting on child")?;
    let _ = p2c.await;
    c2p.abort();
    Ok(status.code().unwrap_or(0) as u32)
}

/// Load the persisted SSH host key, generating and persisting one on first use.
/// Stored as OpenSSH PEM at `<config_dir>/ssh_host_key`, mode 0600.
fn load_or_generate_host_key() -> Result<PrivateKey> {
    use russh::keys::ssh_key::{LineEnding, rand_core::OsRng};

    let path = crate::config::config_dir()?.join("ssh_host_key");
    if path.exists() {
        let pem = std::fs::read_to_string(&path).context("reading ssh host key")?;
        return PrivateKey::from_openssh(&pem).context("parsing ssh host key");
    }
    let key = PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519)
        .context("generating ssh host key")?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .context("encoding ssh host key")?;
    crate::config::write_file(&path, pem.as_bytes(), true)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        let mut b = [0u8; 32];
        b[0] = seed;
        iroh::SecretKey::from(b).public()
    }

    #[test]
    fn authz_matches_identity_and_wildcard_per_network() {
        let alice = id(1);
        let bob = id(2);
        let authz = new_authz();
        let mut map = HashMap::new();
        // `net1` authorizes alice explicitly; `net2` authorizes any peer.
        map.insert("net1".to_string(), vec![alice.to_string()]);
        map.insert("net2".to_string(), vec!["*".to_string()]);
        authz.store(Arc::new(map));

        // alice on net1 → allowed; bob on net1 → denied.
        assert!(is_authorized(&authz, &alice, &[SmolStr::new("net1")]));
        assert!(!is_authorized(&authz, &bob, &[SmolStr::new("net1")]));
        // wildcard on net2 → anyone allowed.
        assert!(is_authorized(&authz, &bob, &[SmolStr::new("net2")]));
        // a network with no allow list → denied.
        assert!(!is_authorized(&authz, &alice, &[SmolStr::new("net3")]));
        // union across shared networks: alice shares net3 (no rule) + net2 (*).
        assert!(is_authorized(
            &authz,
            &alice,
            &[SmolStr::new("net3"), SmolStr::new("net2")]
        ));
    }
}
