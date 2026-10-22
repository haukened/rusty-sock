//! rusty-sock binary: parse arguments and hand off to the library.

use std::process::ExitCode;

use clap::Parser;
use rusty_sock::cli::{Cli, Command};
use rusty_sock::config::Config;

#[tokio::main]
async fn main() -> ExitCode {
    rusty_sock::logging::init();
    let result = match Cli::parse().command {
        Command::Serve { config } => match Config::load(&config) {
            Ok(cfg) => rusty_sock::serve(&cfg, shutdown_signal()).await,
            Err(e) => Err(e.into()),
        },
        Command::HashPassword => {
            rusty_sock::cli::hash_password_cmd(std::io::stdin().lock(), std::io::stdout())
        }
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
