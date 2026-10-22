//! RFC 1929 authentication outcomes over real sockets.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use tokio::io::AsyncReadExt;

async fn read_to_end(c: &mut Client<tokio::net::TcpStream>) -> Vec<u8> {
    let mut rest = Vec::new();
    c.stream.read_to_end(&mut rest).await.unwrap();
    rest
}

#[tokio::test]
async fn good_credentials() {
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    assert_eq!(c.greet(&[0, 2]).await, 2);
    assert_eq!(c.login(USER, PASS).await, 0);
}

#[tokio::test]
async fn bad_password_closes() {
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.greet(&[2]).await;
    assert_ne!(c.login(USER, "nope").await, 0);
    assert_eq!(read_to_end(&mut c).await, [] as [u8; 0]);
}

#[tokio::test]
async fn unknown_user_closes() {
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    c.greet(&[2]).await;
    assert_ne!(c.login("mallory", PASS).await, 0);
    assert_eq!(read_to_end(&mut c).await, [] as [u8; 0]);
}

#[tokio::test]
async fn no_acceptable_method() {
    let proxy = start(ctx(password_auth()), None, 16).await;
    let mut c = Client::connect(proxy.addr).await;
    assert_eq!(c.greet(&[0]).await, 0xFF);
    assert_eq!(read_to_end(&mut c).await, [] as [u8; 0]);
}
