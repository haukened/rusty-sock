//! `rusty-sock user ...` through the real binary, checked against a running
//! server.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::*;

/// Run `rusty-sock user <args> --users-file <users>` with `stdin` piped in.
fn user(users: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rusty-sock"))
        .arg("user")
        .args(args)
        .arg("--users-file")
        .arg(users)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// Start a server on the users file and try a login.
async fn login_works(dir: &Path, users: &Path, name: &str, pass: &str) -> bool {
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "listen = \"127.0.0.1:0\"\n[auth]\nusers_file = \"{}\"\n[dns]\nnameservers = [\"127.0.0.1:53\"]\n",
            users.display()
        ),
    )
    .unwrap();
    let (_proxy, addr) = spawn_server(&config, None);
    let mut c = Client::connect(addr).await;
    assert_eq!(c.greet(&[2]).await, 2);
    c.login(name, pass).await == 0
}

#[tokio::test]
async fn manage_users_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users");

    let out = user(
        &users,
        &["create", "alice", "--password-stdin"],
        "first-pw\n",
    );
    assert!(out.status.success(), "{out:?}");
    assert!(stdout(&out).contains("created user `alice`"));
    assert!(
        stdout(&out).contains("restart to apply"),
        "hint without --restart"
    );
    let mode = std::fs::metadata(&users).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(login_works(dir.path(), &users, "alice", "first-pw").await);

    let out = user(&users, &["create", "bob", "--password-stdin"], "bob-pw\n");
    assert!(out.status.success());
    let out = user(&users, &["list"], "");
    assert_eq!(stdout(&out), "alice\nbob\n");
    assert!(
        !stdout(&out).contains("$argon2"),
        "list never prints hashes"
    );

    let out = user(
        &users,
        &["update", "alice", "--password-stdin"],
        "second-pw\n",
    );
    assert!(out.status.success(), "{out:?}");
    assert!(!login_works(dir.path(), &users, "alice", "first-pw").await);
    assert!(login_works(dir.path(), &users, "alice", "second-pw").await);

    let out = user(&users, &["delete", "alice"], "");
    assert!(out.status.success());
    assert!(!login_works(dir.path(), &users, "alice", "second-pw").await);
    assert!(login_works(dir.path(), &users, "bob", "bob-pw").await);
}

#[test]
fn errors_exit_nonzero_with_message() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users");
    let out = user(&users, &["delete", "nobody"], "");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.starts_with("rusty-sock: ") && err.contains("does not exist"),
        "{err}"
    );

    let out = user(&users, &["create", "bad:name", "--password-stdin"], "pw\n");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid username"));
}
