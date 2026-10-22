//! DNS: server-side resolution with the real resolver, and raw DNS queries
//! through UDP ASSOCIATE.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use rusty_sock::config::DnsConfig;
use rusty_sock::resolver::{HickoryResolver, Resolve};
use rusty_sock::session::Authenticator;
use tokio::net::UdpSocket;

#[tokio::test]
async fn hickory_resolver_uses_configured_nameserver() {
    let dns = dns_server([10, 1, 2, 3]).await;
    let cfg = DnsConfig {
        nameservers: vec![dns],
    };
    let resolver = HickoryResolver::new(&cfg, Duration::from_secs(2)).unwrap();
    let ips = resolver.lookup("example.test").await.unwrap();
    assert!(ips.contains(&"10.1.2.3".parse().unwrap()), "{ips:?}");
}

#[tokio::test]
async fn hickory_resolver_system_config() {
    // Only checks construction from /etc/resolv.conf, if present.
    if std::path::Path::new("/etc/resolv.conf").exists() {
        assert!(HickoryResolver::new(&DnsConfig::default(), Duration::from_secs(1)).is_ok());
    }
}

/// Encapsulate a payload for the relay.
fn wrap(target: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    out.extend_from_slice(target);
    out.extend_from_slice(payload);
    out
}

async fn associate(
    proxy: SocketAddr,
    declared: SocketAddr,
) -> (Client<tokio::net::TcpStream>, SocketAddr) {
    let mut c = Client::connect(proxy).await;
    c.authenticate().await;
    let (rep, relay) = c.request(3, &ip_target(declared)).await;
    assert_eq!(rep, 0);
    (c, relay)
}

async fn recv(sock: &UdpSocket) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(SHORT, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
}

#[tokio::test]
async fn dns_query_through_udp_associate() {
    let dns = dns_server([93, 184, 216, 34]).await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_control, relay) = associate(proxy.addr, sock.local_addr().unwrap()).await;
    sock.connect(relay).await.unwrap();

    let query = dns_query(0x1234, "example.com");
    sock.send(&wrap(&ip_target(dns), &query)).await.unwrap();
    let reply = recv(&sock).await.expect("relayed DNS answer");
    // Header: RSV RSV FRAG + source address of the DNS server.
    let header = [&[0u8, 0, 0][..], &ip_target(dns)].concat();
    assert_eq!(&reply[..header.len()], header.as_slice());
    let answer = &reply[header.len()..];
    assert_eq!(&answer[..2], &[0x12, 0x34]);
    assert_eq!(&answer[answer.len() - 4..], &[93, 184, 216, 34]);

    // Domain-addressed datagrams are resolved by the proxy.
    sock.send(&wrap(
        &domain_target("upstream.test", dns.port()),
        &dns_query(7, "a.b"),
    ))
    .await
    .unwrap();
    assert!(recv(&sock).await.is_some());
}

#[tokio::test]
async fn drops_fragments_and_foreign_sources() {
    let dns = dns_server([1, 1, 1, 1]).await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_control, relay) = associate(proxy.addr, sock.local_addr().unwrap()).await;
    sock.connect(relay).await.unwrap();

    let mut frag = wrap(&ip_target(dns), &dns_query(1, "x.y"));
    frag[2] = 1;
    sock.send(&frag).await.unwrap();
    assert!(recv(&sock).await.is_none(), "fragment must be dropped");

    // A different source port than the one declared in the request.
    let intruder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    intruder.connect(relay).await.unwrap();
    intruder
        .send(&wrap(&ip_target(dns), &dns_query(2, "x.y")))
        .await
        .unwrap();
    assert!(
        recv(&intruder).await.is_none(),
        "foreign source must be dropped"
    );

    // Unsolicited datagrams to the client are not possible: the relay only
    // forwards replies from peers the client contacted. Malformed headers
    // are ignored too.
    sock.send(&[0, 0]).await.unwrap();
    sock.send(&wrap(&ip_target(dns), &dns_query(3, "x.y")))
        .await
        .unwrap();
    assert!(recv(&sock).await.is_some(), "association still works");
}

#[tokio::test]
async fn policy_applies_to_datagrams() {
    let dns = dns_server([1, 1, 1, 1]).await;
    let mut c = ctx(password_auth());
    c.policy = rusty_sock::policy::EgressPolicy::default();
    let proxy = start(c, None, 16).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_control, relay) = associate(proxy.addr, sock.local_addr().unwrap()).await;
    sock.connect(relay).await.unwrap();
    sock.send(&wrap(&ip_target(dns), &dns_query(1, "x.y")))
        .await
        .unwrap();
    assert!(recv(&sock).await.is_none(), "loopback DNS server is denied");
}

#[tokio::test]
async fn association_ends_with_control_connection() {
    let dns = dns_server([1, 1, 1, 1]).await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Unknown source (0.0.0.0:0): the first datagram's port is locked in.
    let (control, relay) = associate(proxy.addr, "0.0.0.0:0".parse().unwrap()).await;
    sock.connect(relay).await.unwrap();
    sock.send(&wrap(&ip_target(dns), &dns_query(1, "x.y")))
        .await
        .unwrap();
    assert!(recv(&sock).await.is_some());

    drop(control);
    tokio::time::sleep(SHORT).await;
    let _ = sock
        .send(&wrap(&ip_target(dns), &dns_query(2, "x.y")))
        .await;
    assert!(
        recv(&sock).await.is_none(),
        "relay closed with control stream"
    );
}

#[tokio::test]
async fn association_idle_timeout() {
    let mut c = ctx(Authenticator::None);
    c.timeouts.udp_idle = Duration::from_millis(100);
    let proxy = start(c, None, 16).await;
    let mut client = Client::connect(proxy.addr).await;
    client.greet(&[0]).await;
    let (rep, _) = client
        .request(3, &ip_target("0.0.0.0:0".parse().unwrap()))
        .await;
    assert_eq!(rep, 0);
    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client.stream, &mut buf)
        .await
        .unwrap();
    assert_eq!(buf, [] as [u8; 0], "server closed the control connection");
}

#[tokio::test]
async fn stray_control_data_is_ignored() {
    use tokio::io::AsyncWriteExt;
    let dns = dns_server([1, 1, 1, 1]).await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut control, relay) = associate(proxy.addr, sock.local_addr().unwrap()).await;
    sock.connect(relay).await.unwrap();
    control.stream.write_all(b"junk").await.unwrap();
    sock.send(&wrap(&ip_target(dns), &dns_query(1, "x.y")))
        .await
        .unwrap();
    assert!(recv(&sock).await.is_some());
}
