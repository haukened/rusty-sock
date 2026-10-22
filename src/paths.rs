//! Standard file locations and systemd credential lookup.
//!
//! A path is chosen in this order:
//! 1. an explicit value from the config file;
//! 2. `$CREDENTIALS_DIRECTORY/<credential>` if that file exists (systemd
//!    `LoadCredential=`, which lets a `DynamicUser=` service read root-owned
//!    secrets);
//! 3. the default under `/etc/rusty-sock/`.

use std::path::{Path, PathBuf};

/// Default config file.
pub const DEFAULT_CONFIG: &str = "/etc/rusty-sock/config.toml";
/// Default users file.
pub const DEFAULT_USERS: &str = "/etc/rusty-sock/users";
/// Default TLS certificate chain.
pub const DEFAULT_TLS_CERT: &str = "/etc/rusty-sock/tls/cert.pem";
/// Default TLS private key.
pub const DEFAULT_TLS_KEY: &str = "/etc/rusty-sock/tls/key.pem";

/// Credential name for the users file.
pub const CRED_USERS: &str = "users";
/// Credential name for the TLS certificate chain.
pub const CRED_TLS_CERT: &str = "tls-cert";
/// Credential name for the TLS private key.
pub const CRED_TLS_KEY: &str = "tls-key";

/// Environment variable systemd sets when credentials are loaded.
pub const CREDENTIALS_ENV: &str = "CREDENTIALS_DIRECTORY";

/// The systemd credentials directory, if this process was given one.
#[must_use]
pub fn credentials_dir() -> Option<PathBuf> {
    credentials_dir_from(std::env::var_os(CREDENTIALS_ENV))
}

/// Interpret a `CREDENTIALS_DIRECTORY` value; empty means unset.
#[must_use]
pub fn credentials_dir_from(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    value.filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// Pick a path: explicit value, then credential, then default.
#[must_use]
pub fn resolve(
    explicit: Option<&Path>,
    credential: &str,
    default: &str,
    creds_dir: Option<&Path>,
) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    creds_dir
        .map(|dir| dir.join(credential))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from(default))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_creds() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn explicit_wins() {
        let guard = temp_creds();
        let dir = guard.path().to_path_buf();
        std::fs::write(dir.join(CRED_USERS), "").unwrap();
        let got = resolve(
            Some(Path::new("/x/users")),
            CRED_USERS,
            DEFAULT_USERS,
            Some(&dir),
        );
        assert_eq!(got, PathBuf::from("/x/users"));
    }

    #[test]
    fn credential_before_default() {
        let guard = temp_creds();
        let dir = guard.path().to_path_buf();
        std::fs::write(dir.join(CRED_USERS), "").unwrap();
        assert_eq!(
            resolve(None, CRED_USERS, DEFAULT_USERS, Some(&dir)),
            dir.join(CRED_USERS)
        );
    }

    #[test]
    fn missing_credential_falls_back() {
        let guard = temp_creds();
        let dir = guard.path().to_path_buf();
        let got = resolve(None, CRED_TLS_KEY, DEFAULT_TLS_KEY, Some(&dir));
        assert_eq!(got, PathBuf::from(DEFAULT_TLS_KEY));
        assert_eq!(
            resolve(None, CRED_USERS, DEFAULT_USERS, None),
            PathBuf::from(DEFAULT_USERS)
        );
    }

    #[test]
    fn credentials_env_values() {
        assert_eq!(credentials_dir_from(None), None);
        assert_eq!(credentials_dir_from(Some("".into())), None);
        assert_eq!(
            credentials_dir_from(Some("/run/credentials/x".into())),
            Some(PathBuf::from("/run/credentials/x"))
        );
        // Whatever the environment says, the wrapper agrees with it.
        assert_eq!(
            credentials_dir(),
            credentials_dir_from(std::env::var_os(CREDENTIALS_ENV))
        );
    }
}
