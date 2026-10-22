//! Default paths and systemd credentials, exercised through the real binary.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use common::*;

#[tokio::test]
async fn users_come_from_credentials_directory() {
    let dir_guard = tempfile::tempdir().unwrap();
    let dir = dir_guard.path().to_path_buf();
    let creds = dir.join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    let hash = rusty_sock::auth::hash_password(PASS.as_bytes()).unwrap();
    std::fs::write(creds.join("users"), format!("{USER}:{hash}\n")).unwrap();
    // No users_file in the config: the credential must be used.
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        "listen = \"127.0.0.1:0\"\n[dns]\nnameservers = [\"127.0.0.1:53\"]\n",
    )
    .unwrap();

    let (proxy, addr) = spawn_server(&config, Some(&creds));
    let mut c = Client::connect(addr).await;
    c.authenticate().await;
    drop(proxy);
}
