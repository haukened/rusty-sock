//! Command-line interface.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::Error;
use crate::auth::hash_password;

/// A small, secure SOCKS5 proxy server.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy server.
    Serve {
        /// Path to the TOML config file.
        #[arg(short, long, default_value = crate::paths::DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Read a password from stdin and print an Argon2id hash for the users file.
    HashPassword,
}

/// Read one password line from `input` and write its hash to `output`.
///
/// # Errors
/// I/O errors, an empty password, or a hashing failure.
pub fn hash_password_cmd(mut input: impl BufRead, mut output: impl Write) -> Result<(), Error> {
    let mut line = Zeroizing::new(String::new());
    input.read_line(&mut line)?;
    let password = line.trim_end_matches(['\r', '\n']);
    if password.is_empty() || password.len() > 255 {
        return Err(Error::InvalidPassword);
    }
    writeln!(output, "{}", hash_password(password.as_bytes())?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CredentialStore;

    #[test]
    fn hashes_password_from_stdin() {
        let mut out = Vec::new();
        hash_password_cmd(&b"hunter2\n"[..], &mut out).unwrap();
        let hash = String::from_utf8(out).unwrap();
        assert!(hash.starts_with("$argon2id$"));
        let store = CredentialStore::parse(&format!("u:{}", hash.trim())).unwrap();
        assert!(store.verify(b"u", b"hunter2"));
    }

    #[test]
    fn rejects_empty_or_long_password() {
        assert!(matches!(
            hash_password_cmd(&b"\n"[..], Vec::new()),
            Err(Error::InvalidPassword)
        ));
        let long = "x".repeat(256);
        assert!(matches!(
            hash_password_cmd(long.as_bytes(), Vec::new()),
            Err(Error::InvalidPassword)
        ));
    }

    #[test]
    fn parses_args() {
        let cli = Cli::try_parse_from(["rusty-sock", "serve", "-c", "x.toml"]).unwrap();
        assert!(
            matches!(cli.command, Command::Serve { config } if config.as_path() == std::path::Path::new("x.toml"))
        );
        let cli = Cli::try_parse_from(["rusty-sock", "serve"]).unwrap();
        assert!(
            matches!(cli.command, Command::Serve { config } if config.as_path() == std::path::Path::new(crate::paths::DEFAULT_CONFIG))
        );
        let cli = Cli::try_parse_from(["rusty-sock", "hash-password"]).unwrap();
        assert!(matches!(cli.command, Command::HashPassword));
    }
}
