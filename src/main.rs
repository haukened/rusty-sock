//! rusty-sock binary: parse arguments and hand off to the library.

use std::ffi::OsStr;
use std::process::ExitCode;

use clap::Parser;
use rusty_sock::cli::{Cli, Command, UserIo, run_user};
use rusty_sock::config::Config;
use rusty_sock::users::PasswordPrompt;
use zeroize::Zeroizing;

/// No-echo prompt on the controlling terminal (works under sudo).
struct Tty;

impl PasswordPrompt for Tty {
    fn prompt(&mut self, prompt: &str) -> std::io::Result<Zeroizing<String>> {
        rpassword::prompt_password(prompt).map(Zeroizing::new)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Serve { config } => serve(&config).await,
        Command::User(args) => {
            let mut stdin = std::io::stdin().lock();
            let mut stdout = std::io::stdout();
            let mut io = UserIo {
                stdin: &mut stdin,
                out: &mut stdout,
                prompt: &mut Tty,
                systemctl: OsStr::new("systemctl"),
            };
            match run_user(&args, &mut io) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("rusty-sock: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn serve(config: &std::path::Path) -> ExitCode {
    rusty_sock::logging::init();
    let result = match Config::load(config) {
        Ok(cfg) => rusty_sock::serve(&cfg, shutdown_signal()).await,
        Err(e) => Err(e.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
