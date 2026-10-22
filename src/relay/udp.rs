//! UDP ASSOCIATE relay (RFC 1928 §7).
//!
//! The client sends SOCKS-encapsulated datagrams to a relay socket bound on
//! the same address as the control connection. Payloads go out through a
//! separate socket; replies are accepted only from destinations the client
//! has sent to, and are encapsulated back to the client. The association
//! ends when the control connection closes or goes idle.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;

use crate::connector::Stream;
use crate::proto::{Rep, TargetAddr, reply, udp};
use crate::resolver::resolve_target;
use crate::session::{Conn, Ctx, SessionError};

/// Maximum number of distinct destinations tracked per association.
const MAX_PEERS: usize = 256;
/// Largest UDP payload.
const MAX_DATAGRAM: usize = 65_535;

/// Handle a UDP ASSOCIATE request.
///
/// # Errors
/// Socket setup failures (a failure reply is sent) or control-stream errors.
pub async fn run<S: Stream>(
    mut conn: Conn<S>,
    requested: &TargetAddr,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Ctx,
) -> Result<(), SessionError> {
    let sockets = match Sockets::bind(local.ip().to_canonical()).await {
        Ok(s) => s,
        Err(e) => return Err(conn.fail(Rep::GeneralFailure, e).await),
    };
    conn.send(&reply::encode(Rep::Succeeded, sockets.client.local_addr()?))
        .await?;
    let mut assoc = Association::new(peer.ip().to_canonical(), requested.port());
    let (mut control, _) = conn.into_parts();
    sockets.relay(&mut assoc, &mut control, ctx).await;
    Ok(())
}

struct Sockets {
    client: UdpSocket,
    outbound: UdpSocket,
    dual_stack: bool,
}

impl Sockets {
    async fn bind(local_ip: IpAddr) -> io::Result<Self> {
        let client = UdpSocket::bind((local_ip, 0)).await?;
        let (outbound, dual_stack) = outbound_socket(bind_dual_stack()).await?;
        Ok(Self {
            client,
            outbound,
            dual_stack,
        })
    }

    async fn relay<S: Stream>(&self, assoc: &mut Association, control: &mut S, ctx: &Ctx) {
        let mut from_client = vec![0u8; MAX_DATAGRAM];
        let mut from_remote = vec![0u8; MAX_DATAGRAM];
        let mut ctrl = [0u8; 64];
        loop {
            // Receive errors (e.g. ICMP-induced) disable an arm for this
            // iteration only. Control-stream EOF or error ends the
            // association; stray data on it is ignored.
            tokio::select! {
                Ok((n, src)) = self.client.recv_from(&mut from_client) => {
                    self.forward(assoc, &from_client[..n], src, ctx).await;
                }
                Ok((n, src)) = self.outbound.recv_from(&mut from_remote) => {
                    self.reply(assoc, &from_remote[..n], src).await;
                }
                n = control.read(&mut ctrl) => if n.unwrap_or(0) == 0 { return },
                () = tokio::time::sleep(ctx.timeouts.udp_idle) => return,
            }
        }
    }

    /// Client → destination.
    async fn forward(&self, assoc: &mut Association, dgram: &[u8], src: SocketAddr, ctx: &Ctx) {
        if !assoc.accept_client(src) {
            tracing::debug!(%src, "dropping datagram from unexpected source");
            return;
        }
        let Ok((target, offset)) = udp::parse(dgram) else {
            return;
        };
        let resolved = resolve_target(&*ctx.resolver, &ctx.policy, &target, ctx.timeouts.dns).await;
        let Some(&dst) = resolved.ok().as_ref().and_then(|a| a.first()) else {
            return;
        };
        assoc.note_peer(dst);
        let _ = self
            .outbound
            .send_to(&dgram[offset..], self.outbound_addr(dst))
            .await;
    }

    /// Destination → client.
    async fn reply(&self, assoc: &Association, payload: &[u8], src: SocketAddr) {
        let src = canonical(src);
        if let (Some(client), true) = (assoc.client_addr, assoc.is_peer(src)) {
            let dgram = udp::encode(&TargetAddr::Ip(src), payload);
            let _ = self.client.send_to(&dgram, client).await;
        }
    }

    fn outbound_addr(&self, dst: SocketAddr) -> SocketAddr {
        match dst.ip() {
            IpAddr::V4(ip) if self.dual_stack => {
                SocketAddr::new(ip.to_ipv6_mapped().into(), dst.port())
            }
            _ => dst,
        }
    }
}

/// Prefer a dual-stack socket; fall back to IPv4-only.
async fn outbound_socket(dual: io::Result<UdpSocket>) -> io::Result<(UdpSocket, bool)> {
    match dual {
        Ok(sock) => Ok((sock, true)),
        Err(_) => Ok((UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?, false)),
    }
}

fn bind_dual_stack() -> io::Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
    sock.set_only_v6(false)?;
    sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Per-association access control state.
#[derive(Debug)]
struct Association {
    client_ip: IpAddr,
    client_port: Option<u16>,
    client_addr: Option<SocketAddr>,
    peers: HashSet<SocketAddr>,
}

impl Association {
    /// `requested_port` is the client's declared source port; 0 means
    /// unknown, in which case the first datagram's port is locked in.
    fn new(client_ip: IpAddr, requested_port: u16) -> Self {
        let client_port = (requested_port != 0).then_some(requested_port);
        Self {
            client_ip,
            client_port,
            client_addr: None,
            peers: HashSet::new(),
        }
    }

    fn accept_client(&mut self, src: SocketAddr) -> bool {
        let src = canonical(src);
        if src.ip() != self.client_ip || self.client_port.is_some_and(|p| p != src.port()) {
            return false;
        }
        self.client_port = Some(src.port());
        self.client_addr = Some(src);
        true
    }

    fn note_peer(&mut self, dst: SocketAddr) {
        if self.peers.len() < MAX_PEERS {
            self.peers.insert(canonical(dst));
        }
    }

    fn is_peer(&self, src: SocketAddr) -> bool {
        self.peers.contains(&src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn locks_to_declared_port() {
        let mut a = Association::new("10.0.0.1".parse().unwrap(), 5000);
        assert!(!a.accept_client(sa("10.0.0.1:5001")));
        assert!(!a.accept_client(sa("10.0.0.2:5000")));
        assert!(a.accept_client(sa("10.0.0.1:5000")));
        assert_eq!(a.client_addr, Some(sa("10.0.0.1:5000")));
    }

    #[test]
    fn locks_to_first_port_when_unknown() {
        let mut a = Association::new("10.0.0.1".parse().unwrap(), 0);
        assert!(a.accept_client(sa("[::ffff:10.0.0.1]:6000")));
        assert!(!a.accept_client(sa("10.0.0.1:6001")));
        assert!(a.accept_client(sa("10.0.0.1:6000")));
    }

    #[test]
    fn peer_set_is_capped() {
        let mut a = Association::new("10.0.0.1".parse().unwrap(), 0);
        for port in 0..=u16::try_from(MAX_PEERS).unwrap() {
            a.note_peer(SocketAddr::new("1.1.1.1".parse().unwrap(), port));
        }
        assert_eq!(a.peers.len(), MAX_PEERS);
        assert!(a.is_peer(sa("1.1.1.1:0")));
        assert!(!a.is_peer(sa("1.1.1.1:256")));
    }

    #[tokio::test]
    async fn falls_back_to_ipv4_outbound() {
        let (sock, dual) = outbound_socket(Err(io::Error::other("no v6")))
            .await
            .unwrap();
        assert!(!dual);
        assert!(sock.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn bind_failure_sends_failure_reply() {
        use crate::session::tests::ctx;
        use tokio::io::AsyncReadExt;
        let c = ctx(crate::session::Authenticator::None);
        let (mut client, server) = tokio::io::duplex(256);
        let conn = Conn::new(server);
        // TEST-NET-1 is never assigned locally, so binding fails.
        let res = run(
            conn,
            &TargetAddr::Ip(sa("0.0.0.0:0")),
            sa("127.0.0.1:1"),
            sa("192.0.2.1:1080"),
            &c,
        )
        .await;
        assert!(matches!(res, Err(SessionError::Io(_))));
        let mut out = [0u8; 4];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(out[1], Rep::GeneralFailure as u8);
    }

    #[tokio::test]
    async fn ignores_unsolicited_replies() {
        let s = Sockets::bind("127.0.0.1".parse().unwrap()).await.unwrap();
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut a = Association::new("127.0.0.1".parse().unwrap(), 0);
        // No client yet: nothing is sent.
        s.reply(&a, b"x", sa("1.1.1.1:53")).await;
        assert!(a.accept_client(probe.local_addr().unwrap()));
        // Client known, but source was never contacted.
        s.reply(&a, b"x", sa("1.1.1.1:53")).await;
        let mut buf = [0u8; 16];
        let got =
            tokio::time::timeout(std::time::Duration::from_millis(100), probe.recv(&mut buf)).await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn maps_v4_destinations_on_dual_stack() {
        let s = Sockets::bind("127.0.0.1".parse().unwrap()).await.unwrap();
        let dst = sa("1.2.3.4:53");
        let mapped = s.outbound_addr(dst);
        if s.dual_stack {
            assert_eq!(mapped, sa("[::ffff:1.2.3.4]:53"));
        } else {
            assert_eq!(mapped, dst);
        }
        assert_eq!(
            s.outbound_addr(sa("[2001:db8::1]:53")),
            sa("[2001:db8::1]:53")
        );
    }
}
