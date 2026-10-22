//! Username/password credential store backed by Argon2id password hashes.
//!
//! The users file holds one `username:$argon2id$...` entry per line. Blank
//! lines and lines starting with `#` are ignored.

use std::path::Path;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash};
use subtle::ConstantTimeEq;

/// Errors loading or creating credentials.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The users file could not be read.
    #[error("cannot read users file: {0}")]
    Io(#[from] std::io::Error),
    /// A line was malformed.
    #[error("users file line {line}: {reason}")]
    Malformed {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        reason: &'static str,
    },
    /// Password hashing failed.
    #[error("password hashing failed: {0}")]
    Hash(password_hash::Error),
}

#[derive(Debug, Clone)]
struct Entry {
    username: Vec<u8>,
    hash: String,
}

/// An immutable set of users and their password hashes.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    entries: Vec<Entry>,
    dummy_hash: String,
}

impl CredentialStore {
    /// Parse the contents of a users file.
    ///
    /// # Errors
    /// Returns [`AuthError::Malformed`] for invalid lines or duplicate users.
    pub fn parse(contents: &str) -> Result<Self, AuthError> {
        let mut entries: Vec<Entry> = Vec::new();
        for (idx, raw) in contents.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = parse_line(line).map_err(|reason| AuthError::Malformed {
                line: idx + 1,
                reason,
            })?;
            if entries.iter().any(|e| e.username == entry.username) {
                return Err(AuthError::Malformed {
                    line: idx + 1,
                    reason: "duplicate username",
                });
            }
            entries.push(entry);
        }
        let dummy_hash = hash_password(b"rusty-sock dummy password")?;
        Ok(Self {
            entries,
            dummy_hash,
        })
    }

    /// Read and parse a users file, warning if it is readable by others.
    ///
    /// # Errors
    /// I/O or parse errors.
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        warn_if_insecure(path);
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Number of configured users.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no users are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verify a username/password pair.
    ///
    /// The username lookup does not short-circuit, and unknown users are
    /// verified against a dummy hash, so response timing does not reveal
    /// whether a username exists. This is CPU-heavy; call it from a
    /// blocking task.
    #[must_use]
    pub fn verify(&self, username: &[u8], password: &[u8]) -> bool {
        let mut found: Option<&str> = None;
        for entry in &self.entries {
            if bool::from(entry.username.ct_eq(username)) {
                found = Some(&entry.hash);
            }
        }
        let hash = found.unwrap_or(&self.dummy_hash);
        verify_hash(hash, password) && found.is_some()
    }
}

fn parse_line(line: &str) -> Result<Entry, &'static str> {
    let (user, hash) = split_entry(line)?;
    Ok(Entry {
        username: user.as_bytes().to_vec(),
        hash: hash.to_owned(),
    })
}

/// Validate one `username:hash` line and split it. Shared with the users
/// file editor so both apply exactly the same rules.
pub(crate) fn split_entry(line: &str) -> Result<(&str, &str), &'static str> {
    let (user, hash) = line.split_once(':').ok_or("expected `username:hash`")?;
    if user.is_empty() || user.len() > 255 {
        return Err("username must be 1-255 bytes");
    }
    let parsed = PasswordHash::new(hash).map_err(|_| "invalid PHC hash string")?;
    if parsed.algorithm != argon2::ARGON2ID_IDENT {
        return Err("hash must be argon2id");
    }
    Ok((user, hash))
}

fn verify_hash(hash: &str, password: &[u8]) -> bool {
    Argon2::default().verify_password(password, hash).is_ok()
}

/// Hash a password with Argon2id and a random salt, returning a PHC string.
///
/// # Errors
/// Returns [`AuthError::Hash`] if hashing fails.
pub fn hash_password(password: &[u8]) -> Result<String, AuthError> {
    // The salt comes from the OS RNG (getrandom).
    Argon2::default()
        .hash_password(password)
        .map(|h| h.to_string())
        .map_err(AuthError::Hash)
}

/// Whether a Unix file mode grants any access to group or others.
#[must_use]
pub fn is_mode_insecure(mode: u32) -> bool {
    mode & 0o077 != 0
}

fn warn_if_insecure(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && is_mode_insecure(meta.permissions().mode())
    {
        tracing::warn!(path = %path.display(), "users file is accessible by group/others; chmod 600 recommended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    static ALICE_HASH: LazyLock<String> = LazyLock::new(|| hash_password(b"wonderland").unwrap());

    fn store() -> CredentialStore {
        CredentialStore::parse(&format!("# users\n\nalice:{}\n", *ALICE_HASH)).unwrap()
    }

    #[test]
    fn verifies_known_user() {
        let s = store();
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
        assert!(s.verify(b"alice", b"wonderland"));
    }

    #[test]
    fn rejects_bad_password_and_unknown_user() {
        let s = store();
        assert!(!s.verify(b"alice", b"wrong"));
        assert!(!s.verify(b"bob", b"wonderland"));
        assert!(!s.verify(b"bob", b"rusty-sock dummy password"));
    }

    #[test]
    fn empty_store() {
        let s = CredentialStore::parse("").unwrap();
        assert_eq!(s.len(), 0);
        assert!(!s.verify(b"alice", b"x"));
    }

    #[test]
    fn malformed_lines() {
        let cases = [
            ("no-colon", "expected `username:hash`"),
            (
                ":$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
                "username must be 1-255 bytes",
            ),
            ("alice:not-a-hash", "invalid PHC hash string"),
            (
                "alice:$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
                "hash must be argon2id",
            ),
        ];
        for (line, want) in cases {
            let err = CredentialStore::parse(line).unwrap_err();
            assert!(
                matches!(err, AuthError::Malformed { line: 1, reason } if reason == want),
                "{line}"
            );
        }
        let long = format!("{}:{}", "u".repeat(256), *ALICE_HASH);
        assert!(CredentialStore::parse(&long).is_err());
    }

    #[test]
    fn duplicate_user() {
        let text = format!("alice:{h}\nalice:{h}\n", h = *ALICE_HASH);
        let err = CredentialStore::parse(&text).unwrap_err();
        assert_eq!(err.to_string(), "users file line 2: duplicate username");
    }

    /// Hash produced by the released v0.1.0 binary (argon2 0.5). Users files
    /// written by older releases must keep working after dependency bumps.
    const V0_1_0_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$cN5shZgLnWaeQebxr1a3YA$YJ0hYIh+wyAXKZU9YdVo1D8wXErBChlc+rGVtNde3xo";

    #[test]
    fn verifies_hashes_from_v0_1_0() {
        let s = CredentialStore::parse(&format!("old:{V0_1_0_HASH}")).unwrap();
        assert!(s.verify(b"old", b"compat-password"));
        assert!(!s.verify(b"old", b"wrong"));
    }

    #[test]
    fn new_hashes_use_same_parameters() {
        // Same algorithm and cost as v0.1.0, so timing for unknown users (the
        // dummy hash) matches real users.
        let hash = hash_password(b"x").unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
    }

    #[test]
    fn corrupt_stored_hash_fails_closed() {
        assert!(!verify_hash("garbage", b"x"));
    }

    #[test]
    fn mode_check() {
        assert!(!is_mode_insecure(0o100_600));
        assert!(is_mode_insecure(0o100_640));
        assert!(is_mode_insecure(0o100_604));
    }

    #[test]
    fn load_from_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir_guard = tempfile::tempdir().unwrap();
        let dir = dir_guard.path().to_path_buf();
        let path = dir.join("users");
        std::fs::write(&path, format!("alice:{}\n", *ALICE_HASH)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            CredentialStore::load(&path)
                .unwrap()
                .verify(b"alice", b"wonderland")
        );
        assert!(matches!(
            CredentialStore::load(&dir.join("missing")),
            Err(AuthError::Io(_))
        ));
    }
}
