//! Policy denial, unsupported commands, timeouts and connection caps.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use rusty_sock::policy::EgressPolicy;
use rusty_sock::session::Authenticator;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn private_destination_denied_by_default() {
    let upstream = http_server("127.0.0.1:0").await;
    let mut c = ctx(Authenticator::None);
    c.policy = EgressPolicy::default();
    let proxy = start(c, None, 16).await;
    let mut client = Client::connect(proxy.addr).await;
    client.greet(&[0]).await;
    let (rep, _) = client.request(1, &ip_target(upstream)).await;
    assert_eq!(rep, 2);
    let (rep, _) = {
        let mut c2 = Client::connect(proxy.addr).await;
        c2.greet(&[0]).await;
        c2.request(1, &domain_target("upstream.test", upstream.port()))
            .await
    };
    assert_eq!(
        rep, 2,
        "DNS answers pointing at private ranges are denied too"
    );
}

#[tokio::test]
async fn bind_not_supported() {
    let proxy = start(ctx(Authenticator::None), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.greet(&[0]).await;
    let (rep, _) = c
        .request(2, &ip_target("127.0.0.1:0".parse().unwrap()))
        .await;
    assert_eq!(rep, 7);
}

#[tokio::test]
async fn handshake_timeout_closes() {
    let mut c = ctx(Authenticator::None);
    c.timeouts.handshake = SHORT;
    let proxy = start(c, None, 16).await;
    let mut client = Client::connect(proxy.addr).await;
    let mut buf = Vec::new();
    client.stream.read_to_end(&mut buf).await.unwrap();
    assert_eq!(buf, [] as [u8; 0]);
}

#[tokio::test]
async fn connection_cap() {
    let proxy = start(ctx(Authenticator::None), None, 1).await;
    let mut first = Client::connect(proxy.addr).await;
    assert_eq!(first.greet(&[0]).await, 0);
    let mut second = Client::connect(proxy.addr).await;
    let mut buf = Vec::new();
    let _ = second.stream.read_to_end(&mut buf).await;
    assert_eq!(buf, [] as [u8; 0], "over-limit connection is dropped");
}
