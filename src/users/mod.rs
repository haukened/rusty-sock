//! User management: `rusty-sock user {create,update,delete,list}`.
//!
//! - [`file`]: line-preserving, atomic editing of the users file.
//! - [`input`]: no-echo password prompt with confirmation, or stdin.
//! - [`restart`]: the opt-in `--restart` (`systemctl try-restart`).

mod file;
mod input;
mod restart;

use std::io;
use std::path::{Path, PathBuf};

use crate::auth::AuthError;

pub use file::UsersFile;
pub use input::{PasswordPrompt, hash, prompt_new_password, read_password_line};
pub use restart::{Restart, restart_service};

/// The systemd unit restarted by `--restart`.
pub const UNIT: &str = "rusty-sock.service";
/// Prompt attempts before giving up on mismatched confirmations.
pub const MAX_ATTEMPTS: usize = 3;

/// Errors from user management.
#[derive(Debug, thiserror::Error)]
pub enum UsersError {
    /// Reading or writing a file failed.
    #[error("{path}: {source}{hint}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
        /// Extra advice (e.g. to use sudo).
        hint: &'static str,
    },
    /// The existing users file has an invalid line; it is not modified.
    #[error("{path} line {line}: {reason}; fix it by hand before editing")]
    Malformed {
        /// The users file.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        reason: &'static str,
    },
    /// Another edit is in progress (or a previous one crashed).
    #[error("{0} exists: another edit is in progress; if not, remove it and retry")]
    Locked(PathBuf),
    /// The users file does not exist.
    #[error("{0} does not exist; create a user first")]
    MissingFile(PathBuf),
    /// `create` of a user that already exists.
    #[error("user `{0}` already exists; use `user update` to change the password")]
    Exists(String),
    /// `update`/`delete` of a user that does not exist.
    #[error("no such user `{0}`")]
    NoSuchUser(String),
    /// The username is not allowed.
    #[error("invalid username: {0}")]
    InvalidName(&'static str),
    /// The password is empty or too long.
    #[error("password must be 1-255 bytes")]
    InvalidPassword,
    /// The two entered passwords differed too many times.
    #[error("passwords did not match after {MAX_ATTEMPTS} attempts")]
    PasswordMismatch,
    /// The password prompt could not be shown.
    #[error("cannot prompt for a password ({0}); use --password-stdin")]
    Prompt(io::Error),
    /// Hashing failed.
    #[error(transparent)]
    Hash(#[from] AuthError),
    /// The users file was saved but restarting the service failed.
    #[error("users file updated, but restarting {UNIT} failed: {0}; restart it manually")]
    Restart(String),
}

fn io_error(path: &Path, source: io::Error) -> UsersError {
    let hint = if source.kind() == io::ErrorKind::PermissionDenied {
        " (try again with sudo)"
    } else {
        ""
    };
    UsersError::Io {
        path: path.to_path_buf(),
        source,
        hint,
    }
}

/// Usernames: 1-255 printable ASCII bytes, no whitespace or `:`, and not
/// starting with `#` (which would read back as a comment).
///
/// # Errors
/// [`UsersError::InvalidName`] describing the problem.
pub fn validate_name(name: &str) -> Result<(), UsersError> {
    if name.is_empty() || name.len() > 255 {
        return Err(UsersError::InvalidName("must be 1-255 bytes"));
    }
    if !name.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
        return Err(UsersError::InvalidName(
            "use printable ASCII without spaces or `:`",
        ));
    }
    if name.starts_with('#') {
        return Err(UsersError::InvalidName("must not start with `#`"));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), UsersError> {
    if password.is_empty() || password.len() > 255 {
        return Err(UsersError::InvalidPassword);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_names() {
        for (name, why) in [
            ("", "must be 1-255 bytes"),
            (&"x".repeat(256), "must be 1-255 bytes"),
            ("has space", "use printable ASCII without spaces or `:`"),
            ("co:lon", "use printable ASCII without spaces or `:`"),
            ("tab\tname", "use printable ASCII without spaces or `:`"),
            ("#hash", "must not start with `#`"),
        ] {
            assert!(
                matches!(validate_name(name), Err(UsersError::InvalidName(r)) if r == why),
                "{name:?}"
            );
        }
        assert!(validate_name("alice.smith-01").is_ok());
    }
}
