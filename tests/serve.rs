//! The config-driven entry point: `build` and `serve`.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;
use rusty_sock::config::Config;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rusty-sock-serve-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn serves_from_config_file() {
    let dir = temp_dir("ok");
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
    let dir = temp_dir("err");
    let mut config = Config::parse("[auth]\nusers_file = \"missing\"\n").unwrap();
    config.auth.users_file = Some(dir.join("missing"));
    assert!(matches!(
        rusty_sock::build(&config).await,
        Err(rusty_sock::Error::Auth(_))
    ));

    config.auth.users_file = None;
    assert!(matches!(
        rusty_sock::build(&config).await,
        Err(rusty_sock::Error::Config(_))
    ));

    let mut config = Config::parse("[auth]\nmode = \"none\"\n").unwrap();
    config.tls = Some(rusty_sock::config::TlsConfig {
        cert: dir.join("nope"),
        key: dir.join("nope"),
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
