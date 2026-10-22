//! HTTP through CONNECT with IPv4, IPv6 and domain targets.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use rusty_sock::session::Authenticator;

#[tokio::test]
async fn http_via_ipv4() {
    let upstream = http_server("127.0.0.1:0").await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.authenticate().await;
    let (rep, bnd) = c.request(1, &ip_target(upstream)).await;
    assert_eq!(rep, 0);
    assert!(bnd.ip().is_loopback());
    let response = http_get(&mut c.stream, "upstream").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with(HTTP_BODY));
}

#[tokio::test]
async fn http_via_domain() {
    let upstream = http_server("127.0.0.1:0").await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.authenticate().await;
    let (rep, _) = c
        .request(1, &domain_target("upstream.test", upstream.port()))
        .await;
    assert_eq!(rep, 0);
    assert!(
        http_get(&mut c.stream, "upstream.test")
            .await
            .ends_with(HTTP_BODY)
    );
}

#[tokio::test]
async fn http_via_ipv6() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    }
    let upstream = http_server("[::1]:0").await;
    let proxy = start(ctx(Authenticator::None), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    assert_eq!(c.greet(&[0]).await, 0);
    let (rep, _) = c.request(1, &ip_target(upstream)).await;
    assert_eq!(rep, 0);
    assert!(
        http_get(&mut c.stream, "upstream")
            .await
            .ends_with(HTTP_BODY)
    );
}

#[tokio::test]
async fn unknown_domain_is_host_unreachable() {
    let proxy = start(ctx(Authenticator::None), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.greet(&[0]).await;
    let (rep, _) = c.request(1, &domain_target("nx.test", 80)).await;
    assert_eq!(rep, 4);
}

#[tokio::test]
async fn refused_port_is_connection_refused() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = start(ctx(Authenticator::None), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.greet(&[0]).await;
    let (rep, _) = c.request(1, &ip_target(closed)).await;
    assert_eq!(rep, 5);
}
