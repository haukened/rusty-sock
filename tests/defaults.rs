//! Default paths and systemd credentials, exercised through the real binary.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

use common::*;

struct Proxy(Child);

impl Drop for Proxy {
    /// Stop with SIGTERM (graceful shutdown path), falling back to SIGKILL.
    fn drop(&mut self) {
        let term = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        if !term.is_ok_and(|s| s.success()) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn temp_dir(_tag: &str) -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// Start the binary and return it once it logs its listening address.
fn spawn(config: &std::path::Path, creds: &std::path::Path) -> (Proxy, SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rusty-sock"))
        .args(["serve", "-c"])
        .arg(config)
        .env("CREDENTIALS_DIRECTORY", creds)
        .env("JOURNAL_STREAM", "8:1234")
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let proxy = Proxy(child);
    let mut lines = BufReader::new(stdout).lines();
    for line in lines.by_ref() {
        let line = line.unwrap();
        assert!(
            !line.contains('\u{1b}'),
            "no ANSI codes when not a terminal: {line}"
        );
        if let Some(addr) = line.split("addr=").nth(1) {
            let addr = addr.split_whitespace().next().unwrap().parse().unwrap();
            // Keep draining so later log lines don't hit a closed pipe.
            std::thread::spawn(move || lines.for_each(drop));
            return (proxy, addr);
        }
    }
    panic!("server exited before listening");
}

#[tokio::test]
async fn users_come_from_credentials_directory() {
    let dir_guard = temp_dir("creds");
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

    let (proxy, addr) = spawn(&config, &creds);
    let mut c = Client::connect(addr).await;
    c.authenticate().await;
    drop(proxy);
}
