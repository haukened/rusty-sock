//! HTTPS through CONNECT: the client completes a TLS handshake with the
//! upstream through the tunnel.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use rustls_pki_types::ServerName;

#[tokio::test]
async fn https_via_connect() {
    let (cert, key) = self_signed();
    let upstream = https_server(&cert, &key).await;
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.authenticate().await;
    let (rep, _) = c
        .request(1, &domain_target("upstream.test", upstream.port()))
        .await;
    assert_eq!(rep, 0);
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = tls_connector(&cert).connect(name, c.stream).await.unwrap();
    let response = http_get(&mut tls, "localhost").await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with(HTTP_BODY));
}
