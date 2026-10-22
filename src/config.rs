//! TOML configuration with secure defaults.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::paths;
use crate::policy::EgressPolicy;

/// Errors loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not valid TOML or has unknown/invalid fields.
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    /// The configuration is unsafe or inconsistent.
    #[error("invalid config: {0}")]
    Invalid(&'static str),
}

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Authentication settings.
    pub auth: AuthConfig,
    /// Optional TLS listener settings.
    pub tls: Option<TlsSection>,
    /// Resource limits and timeouts.
    pub limits: Limits,
    /// Destination filtering.
    pub egress: EgressConfig,
    /// DNS resolver settings.
    pub dns: DnsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 1080)),
            auth: AuthConfig::default(),
            tls: None,
            limits: Limits::default(),
            egress: EgressConfig::default(),
            dns: DnsConfig::default(),
        }
    }
}

/// Client authentication mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Username/password (RFC 1929). The default.
    #[default]
    Password,
    /// No authentication. Must be chosen explicitly.
    None,
}

/// Authentication settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Authentication mode.
    pub mode: AuthMode,
    /// Path to the users file. Defaults to the `users` systemd credential
    /// or `/etc/rusty-sock/users`.
    pub users_file: Option<PathBuf>,
    /// Permit `mode = "none"` on a non-loopback address.
    pub allow_open_proxy: bool,
}

/// The `[tls]` section. Its presence enables TLS; omitted paths default to
/// the `tls-cert`/`tls-key` systemd credentials or `/etc/rusty-sock/tls/`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsSection {
    /// PEM certificate chain.
    pub cert: Option<PathBuf>,
    /// PEM private key.
    pub key: Option<PathBuf>,
}

/// Resolved TLS certificate and key paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert: PathBuf,
    /// PEM private key.
    pub key: PathBuf,
}

/// Resource limits. Durations are in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Maximum concurrent client sessions.
    pub max_connections: usize,
    /// Deadline for TLS + negotiation + auth + request.
    pub handshake_timeout_secs: u64,
    /// Deadline for connecting to a destination.
    pub connect_timeout_secs: u64,
    /// Close relays idle for this long.
    pub idle_timeout_secs: u64,
    /// Deadline for a DNS lookup.
    pub dns_timeout_secs: u64,
    /// Close UDP associations idle for this long.
    pub udp_idle_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            idle_timeout_secs: 300,
            dns_timeout_secs: 5,
            udp_idle_timeout_secs: 120,
        }
    }
}

/// Validated timeouts as [`Duration`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// See [`Limits::handshake_timeout_secs`].
    pub handshake: Duration,
    /// See [`Limits::connect_timeout_secs`].
    pub connect: Duration,
    /// See [`Limits::idle_timeout_secs`].
    pub idle: Duration,
    /// See [`Limits::dns_timeout_secs`].
    pub dns: Duration,
    /// See [`Limits::udp_idle_timeout_secs`].
    pub udp_idle: Duration,
}

impl Limits {
    /// Convert the second-based fields to [`Timeouts`].
    #[must_use]
    pub fn timeouts(&self) -> Timeouts {
        Timeouts {
            handshake: Duration::from_secs(self.handshake_timeout_secs),
            connect: Duration::from_secs(self.connect_timeout_secs),
            idle: Duration::from_secs(self.idle_timeout_secs),
            dns: Duration::from_secs(self.dns_timeout_secs),
            udp_idle: Duration::from_secs(self.udp_idle_timeout_secs),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let secs = [
            self.handshake_timeout_secs,
            self.connect_timeout_secs,
            self.idle_timeout_secs,
            self.dns_timeout_secs,
            self.udp_idle_timeout_secs,
        ];
        if self.max_connections == 0 || secs.contains(&0) {
            return Err(ConfigError::Invalid("limits must be greater than zero"));
        }
        Ok(())
    }
}

/// Destination filtering settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EgressConfig {
    /// Allow private, loopback and other non-public destinations.
    pub allow_private: bool,
    /// If non-empty, only these destination ports are allowed.
    pub allowed_ports: Vec<u16>,
}

impl EgressConfig {
    /// Build the runtime policy.
    #[must_use]
    pub fn policy(&self) -> EgressPolicy {
        EgressPolicy {
            allow_private: self.allow_private,
            allowed_ports: self.allowed_ports.clone(),
        }
    }
}

/// DNS resolver settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Upstream nameservers. Empty means use `/etc/resolv.conf`.
    pub nameservers: Vec<SocketAddr>,
}

impl Config {
    /// Parse and validate a TOML document.
    ///
    /// # Errors
    /// Parse or validation errors.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Read, parse and validate a config file. Relative paths inside it are
    /// resolved against the file's directory.
    ///
    /// # Errors
    /// I/O, parse or validation errors.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut config = Self::parse(&std::fs::read_to_string(path)?)?;
        if let Some(base) = path.parent() {
            config.resolve_paths(base);
        }
        Ok(config)
    }

    fn resolve_paths(&mut self, base: &Path) {
        let tls = self.tls.as_mut().map(|t| [&mut t.cert, &mut t.key]);
        let paths = std::iter::once(&mut self.auth.users_file).chain(tls.into_iter().flatten());
        for path in paths.flatten() {
            *path = base.join(&*path);
        }
    }

    /// The users file: explicit, else the `users` credential, else the
    /// default path.
    #[must_use]
    pub fn users_file(&self, creds_dir: Option<&Path>) -> PathBuf {
        let explicit = self.auth.users_file.as_deref();
        paths::resolve(explicit, paths::CRED_USERS, paths::DEFAULT_USERS, creds_dir)
    }

    /// Resolved TLS paths, if `[tls]` is present.
    #[must_use]
    pub fn tls_paths(&self, creds_dir: Option<&Path>) -> Option<TlsConfig> {
        let tls = self.tls.as_ref()?;
        Some(TlsConfig {
            cert: paths::resolve(
                tls.cert.as_deref(),
                paths::CRED_TLS_CERT,
                paths::DEFAULT_TLS_CERT,
                creds_dir,
            ),
            key: paths::resolve(
                tls.key.as_deref(),
                paths::CRED_TLS_KEY,
                paths::DEFAULT_TLS_KEY,
                creds_dir,
            ),
        })
    }

    /// Check the configuration for unsafe or inconsistent settings.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.limits.validate()?;
        match self.auth.mode {
            AuthMode::None if self.is_exposed() && !self.auth.allow_open_proxy => {
                Err(ConfigError::Invalid(
                    "refusing to run without auth on a non-loopback address; set auth.allow_open_proxy = true to override",
                ))
            }
            _ => Ok(()),
        }
    }

    /// Non-fatal security warnings for this configuration.
    #[must_use]
    pub fn warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        let exposed = self.is_exposed();
        if exposed && self.auth.mode == AuthMode::Password && self.tls.is_none() {
            out.push("password auth over plaintext on a non-loopback address: credentials can be sniffed; consider [tls]");
        }
        if exposed && self.auth.mode == AuthMode::None {
            out.push("running an open proxy without authentication");
        }
        if self.egress.allow_private {
            out.push("egress.allow_private is enabled: clients can reach internal networks");
        }
        out
    }

    fn is_exposed(&self) -> bool {
        !self.listen.ip().is_loopback()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_default_paths() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.auth.mode, AuthMode::Password);
        assert_eq!(c.users_file(None), PathBuf::from(paths::DEFAULT_USERS));
        assert_eq!(c.tls_paths(None), None);
    }

    #[test]
    fn empty_tls_section_uses_defaults_or_credentials() {
        let c = Config::parse("[tls]\n").unwrap();
        let tls = c.tls_paths(None).unwrap();
        assert_eq!(tls.cert, PathBuf::from(paths::DEFAULT_TLS_CERT));
        assert_eq!(tls.key, PathBuf::from(paths::DEFAULT_TLS_KEY));

        let creds_guard = tempfile::tempdir().unwrap();
        let creds = creds_guard.path().to_path_buf();
        std::fs::write(creds.join(paths::CRED_TLS_KEY), "").unwrap();
        std::fs::write(creds.join(paths::CRED_USERS), "").unwrap();
        let tls = c.tls_paths(Some(&creds)).unwrap();
        assert_eq!(tls.cert, PathBuf::from(paths::DEFAULT_TLS_CERT));
        assert_eq!(tls.key, creds.join(paths::CRED_TLS_KEY));
        assert_eq!(c.users_file(Some(&creds)), creds.join(paths::CRED_USERS));
    }

    #[test]
    fn minimal_password_config() {
        let c = Config::parse("[auth]\nusers_file = \"users\"\n").unwrap();
        assert_eq!(c.listen, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(c.auth.mode, AuthMode::Password);
        assert_eq!(c.warnings(), [] as [&str; 0]);
        assert_eq!(c.limits.timeouts().handshake, Duration::from_secs(10));
        assert_eq!(c.egress.policy(), EgressPolicy::default());
    }

    #[test]
    fn full_config() {
        let text = r#"
            listen = "0.0.0.0:1080"
            [auth]
            mode = "password"
            users_file = "users"
            [tls]
            cert = "cert.pem"
            key = "key.pem"
            [limits]
            max_connections = 10
            handshake_timeout_secs = 1
            connect_timeout_secs = 2
            idle_timeout_secs = 3
            dns_timeout_secs = 4
            udp_idle_timeout_secs = 5
            [egress]
            allow_private = true
            allowed_ports = [80, 443]
            [dns]
            nameservers = ["1.1.1.1:53"]
        "#;
        let c = Config::parse(text).unwrap();
        let t = c.limits.timeouts();
        assert_eq!(t.connect, Duration::from_secs(2));
        assert_eq!(t.idle, Duration::from_secs(3));
        assert_eq!(t.dns, Duration::from_secs(4));
        assert_eq!(t.udp_idle, Duration::from_secs(5));
        assert_eq!(c.egress.policy().allowed_ports, vec![80, 443]);
        assert_eq!(c.dns.nameservers.len(), 1);
        assert_eq!(
            c.warnings(),
            vec!["egress.allow_private is enabled: clients can reach internal networks"]
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(matches!(
            Config::parse("bogus = 1"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_zero_limits() {
        let text = "[auth]\nusers_file = \"u\"\n[limits]\nidle_timeout_secs = 0\n";
        assert!(matches!(Config::parse(text), Err(ConfigError::Invalid(_))));
        let text = "[auth]\nusers_file = \"u\"\n[limits]\nmax_connections = 0\n";
        assert!(matches!(Config::parse(text), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn open_proxy_guard() {
        let local = Config::parse("[auth]\nmode = \"none\"\n").unwrap();
        assert_eq!(local.warnings(), [] as [&str; 0]);
        let exposed = "listen = \"0.0.0.0:1080\"\n[auth]\nmode = \"none\"\n";
        assert!(matches!(
            Config::parse(exposed),
            Err(ConfigError::Invalid(_))
        ));
        let c = Config::parse(&format!("{exposed}allow_open_proxy = true\n")).unwrap();
        assert_eq!(
            c.warnings(),
            vec!["running an open proxy without authentication"]
        );
    }

    #[test]
    fn plaintext_password_warning() {
        let c = Config::parse("listen = \"[::]:1080\"\n[auth]\nusers_file = \"u\"\n").unwrap();
        assert_eq!(c.warnings().len(), 1);
        assert!(c.warnings()[0].starts_with("password auth over plaintext"));
    }

    #[test]
    fn load_resolves_relative_paths() {
        let dir_guard = tempfile::tempdir().unwrap();
        let dir = dir_guard.path().to_path_buf();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "[auth]\nusers_file = \"users\"\n[tls]\ncert = \"c.pem\"\nkey = \"/abs/k.pem\"\n",
        )
        .unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.users_file(None), dir.join("users"));
        let tls = c.tls_paths(None).unwrap();
        assert_eq!(tls.cert, dir.join("c.pem"));
        assert_eq!(tls.key, PathBuf::from("/abs/k.pem"));
        assert!(matches!(
            Config::load(&dir.join("missing")),
            Err(ConfigError::Io(_))
        ));
    }
}
