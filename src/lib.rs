//! rusty-sock: a small, secure SOCKS5 proxy server.
//!
//! Implements RFC 1928 (CONNECT and UDP ASSOCIATE) with RFC 1929
//! username/password authentication, an egress policy that blocks
//! non-public destinations by default, and an optional TLS listener.

pub mod auth;
pub mod cli;
pub mod config;
pub mod connector;
pub mod error;
pub mod listener;
pub mod policy;
pub mod proto;
pub mod relay;
pub mod resolver;
pub mod session;
pub mod tls;

use std::future::Future;
use std::sync::Arc;

use crate::auth::CredentialStore;
use crate::config::{AuthMode, Config};
use crate::connector::TcpConnector;
use crate::listener::Server;
use crate::resolver::HickoryResolver;
use crate::session::{Authenticator, Ctx};

/// Top-level errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration problem.
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    /// Credential store problem.
    #[error(transparent)]
    Auth(#[from] auth::AuthError),
    /// TLS setup problem.
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    /// I/O problem (binding, resolver setup, stdin/stdout).
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The password given to `hash-password` was empty or too long.
    #[error("password must be 1-255 bytes")]
    InvalidPassword,
}

/// Build a bound server from a validated config.
///
/// # Errors
/// Credential, TLS, resolver or bind errors.
pub async fn build(config: &Config) -> Result<Server, Error> {
    let auth = match (config.auth.mode, &config.auth.users_file) {
        (AuthMode::Password, Some(path)) => {
            Authenticator::Password(Arc::new(CredentialStore::load(path)?))
        }
        (AuthMode::Password, None) => {
            return Err(config::ConfigError::Invalid("auth.users_file is required").into());
        }
        (AuthMode::None, _) => Authenticator::None,
    };
    let timeouts = config.limits.timeouts();
    let ctx = Ctx {
        auth,
        policy: config.egress.policy(),
        resolver: Arc::new(HickoryResolver::new(&config.dns, timeouts.dns)?),
        connector: Arc::new(TcpConnector),
        timeouts,
    };
    let tls = config.tls.as_ref().map(tls::acceptor).transpose()?;
    Ok(Server::bind(config.listen, ctx, tls, config.limits.max_connections).await?)
}

/// Log warnings, build the server and run it until `shutdown` resolves.
///
/// # Errors
/// See [`build`].
pub async fn serve(config: &Config, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
    for warning in config.warnings() {
        tracing::warn!("{warning}");
    }
    let server = build(config).await?;
    tracing::info!(addr = %server.local_addr()?, tls = config.tls.is_some(), "listening");
    server.run(shutdown).await;
    tracing::info!("shut down");
    Ok(())
}
