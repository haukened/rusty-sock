//! The config-driven entry point: `build` and `serve`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use rusty_sock::config::Config;

fn temp_dir(_tag: &str) -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[tokio::test]
async fn serves_from_config_file() {
    let dir_guard = temp_dir("ok");
    let dir = dir_guard.path().to_path_buf();
    let hash = rusty_sock::auth::hash_password(PASS.as_bytes()).unwrap();
    std::fs::write(dir.join("users"), format!("{USER}:{hash}\n")).unwrap();
    let (cert, key) = self_signed();
    std::fs::write(dir.join("cert.pem"), &cert).unwrap();
    std::fs::write(dir.join("key.pem"), &key).unwrap();
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        "listen = \"127.0.0.1:0\"\n[auth]\nusers_file = \"users\"\n[tls]\ncert = \"cert.pem\"\nkey = \"key.pem\"\n[dns]\nnameservers = [\"127.0.0.1:53\"]\n",
    )
    .unwrap();
    let config = Config::load(&path).unwrap();

    let server = rusty_sock::build(&config).await.unwrap();
    assert!(server.local_addr().unwrap().ip().is_loopback());
    drop(server);

    // `serve` returns once the shutdown future resolves.
    rusty_sock::serve(&config, async {}).await.unwrap();
}

#[tokio::test]
async fn serve_without_auth() {
    let config = Config::parse(
        "listen = \"127.0.0.1:0\"\n[auth]\nmode = \"none\"\n[egress]\nallow_private = true\n",
    )
    .unwrap();
    rusty_sock::serve(&config, async {}).await.unwrap();
}

#[tokio::test]
async fn build_errors() {
    let dir_guard = temp_dir("err");
    let dir = dir_guard.path().to_path_buf();
    let mut config = Config::parse("[auth]\nusers_file = \"missing\"\n").unwrap();
    config.auth.users_file = Some(dir.join("missing"));
    assert!(matches!(
        rusty_sock::build(&config).await,
        Err(rusty_sock::Error::Auth(_))
    ));

    // No users_file: falls back to /etc/rusty-sock/users, which is absent
    // (or root-only) on test machines.
    config.auth.users_file = None;
    assert!(matches!(
        rusty_sock::build(&config).await,
        Err(rusty_sock::Error::Auth(_))
    ));

    let mut config = Config::parse("[auth]\nmode = \"none\"\n").unwrap();
    config.tls = Some(rusty_sock::config::TlsSection {
        cert: Some(dir.join("nope")),
        key: Some(dir.join("nope")),
    });
    assert!(matches!(
        rusty_sock::build(&config).await,
        Err(rusty_sock::Error::Tls(_))
    ));

    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut config = Config::parse("[auth]\nmode = \"none\"\n").unwrap();
    config.listen = taken.local_addr().unwrap();
    let err = rusty_sock::serve(&config, async {}).await.unwrap_err();
    assert!(matches!(err, rusty_sock::Error::Io(_)), "{err}");
}

#[tokio::test]
async fn empty_users_file_starts_with_warning() {
    let dir_guard = temp_dir("empty");
    let dir = dir_guard.path().to_path_buf();
    std::fs::write(dir.join("users"), "# no users yet\n").unwrap();
    let mut config = Config::parse("listen = \"127.0.0.1:0\"\n").unwrap();
    config.auth.users_file = Some(dir.join("users"));
    let server = rusty_sock::build(&config).await.unwrap();
    let proxy = server.local_addr().unwrap();
    tokio::spawn(server.run(std::future::pending()));
    let mut c = Client::connect(proxy).await;
    c.greet(&[2]).await;
    assert_ne!(c.login(USER, PASS).await, 0);
}
