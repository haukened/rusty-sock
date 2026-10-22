//! The full SOCKS flow over the TLS listener.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use rustls_pki_types::ServerName;

#[tokio::test]
async fn socks_over_tls() {
    let (cert, key) = self_signed();
    let (_dir, tls_cfg) = write_tls_files(&cert, &key);
    let acceptor = rusty_sock::tls::acceptor(&tls_cfg).unwrap();
    let upstream = http_server("127.0.0.1:0").await;
    let proxy = start(ctx(password_auth()), Some(acceptor), 16).await;

    let tcp = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let stream = tls_connector(&cert).connect(name, tcp).await.unwrap();
    let mut c = Client { stream };
    c.authenticate().await;
    let (rep, _) = c.request(1, &ip_target(upstream)).await;
    assert_eq!(rep, 0);
    assert!(
        http_get(&mut c.stream, "upstream")
            .await
            .ends_with(HTTP_BODY)
    );
}

#[tokio::test]
async fn plaintext_client_rejected_by_tls_listener() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (cert, key) = self_signed();
    let acceptor = rusty_sock::tls::acceptor(&write_tls_files(&cert, &key).1).unwrap();
    let proxy = start(ctx(password_auth()), Some(acceptor), 16).await;
    let mut tcp = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    tcp.write_all(&[5, 1, 2]).await.unwrap();
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf).await;
    assert!(!buf.starts_with(&[5]));
}

#[tokio::test]
async fn tls_handshake_timeout() {
    let (cert, key) = self_signed();
    let acceptor = rusty_sock::tls::acceptor(&write_tls_files(&cert, &key).1).unwrap();
    let mut c = ctx(password_auth());
    c.timeouts.handshake = SHORT;
    let proxy = start(c, Some(acceptor), 16).await;
    let mut tcp = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut buf)
        .await
        .unwrap_or(0);
    assert_eq!(n, 0);
}
