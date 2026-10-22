//! Reading a new password: no-echo prompt with confirmation, or one line
//! from stdin (`--password-stdin`).

use std::io::{self, BufRead, Write};
use std::path::Path;

use zeroize::Zeroizing;

use super::{MAX_ATTEMPTS, UsersError, io_error, validate_password};
use crate::auth::hash_password;

/// Something that can ask for a password without echoing it.
pub trait PasswordPrompt {
    /// Show `prompt` and read one password.
    ///
    /// # Errors
    /// If no terminal is available or reading fails.
    fn prompt(&mut self, prompt: &str) -> io::Result<Zeroizing<String>>;
}

/// Ask for a new password twice, retrying on mismatch.
///
/// # Errors
/// [`UsersError::Prompt`], [`UsersError::InvalidPassword`] or
/// [`UsersError::PasswordMismatch`].
pub fn prompt_new_password(
    name: &str,
    prompt: &mut dyn PasswordPrompt,
    out: &mut dyn Write,
) -> Result<Zeroizing<String>, UsersError> {
    for _ in 0..MAX_ATTEMPTS {
        let first = prompt
            .prompt(&format!("Password for {name}: "))
            .map_err(UsersError::Prompt)?;
        validate_password(&first)?;
        let second = prompt
            .prompt("Confirm password: ")
            .map_err(UsersError::Prompt)?;
        if first == second {
            return Ok(first);
        }
        let _ = writeln!(out, "passwords do not match, try again");
    }
    Err(UsersError::PasswordMismatch)
}

/// Read a password as one line from `input` (for `--password-stdin`).
///
/// # Errors
/// I/O errors or [`UsersError::InvalidPassword`].
pub fn read_password_line(input: &mut dyn BufRead) -> Result<Zeroizing<String>, UsersError> {
    let mut line = Zeroizing::new(String::new());
    input
        .read_line(&mut line)
        .map_err(|e| io_error(Path::new("<stdin>"), e))?;
    let password = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned());
    validate_password(&password)?;
    Ok(password)
}

/// Hash a password for the users file.
///
/// # Errors
/// If hashing fails.
pub fn hash(password: &str) -> Result<String, UsersError> {
    Ok(hash_password(password.as_bytes())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Scripted(VecDeque<io::Result<&'static str>>);

    impl PasswordPrompt for Scripted {
        fn prompt(&mut self, _: &str) -> io::Result<Zeroizing<String>> {
            self.0
                .pop_front()
                .unwrap_or(Ok(""))
                .map(|s| Zeroizing::new(s.to_owned()))
        }
    }

    fn scripted(answers: &[&'static str]) -> Scripted {
        Scripted(answers.iter().map(|a| Ok(*a)).collect())
    }

    #[test]
    fn prompt_confirms_and_retries() {
        let mut out = Vec::new();
        let pw = prompt_new_password(
            "alice",
            &mut scripted(&["one", "two", "pw", "pw"]),
            &mut out,
        )
        .unwrap();
        assert_eq!(pw.as_str(), "pw");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "passwords do not match, try again\n"
        );
    }

    #[test]
    fn prompt_gives_up_after_max_attempts() {
        let answers = ["a", "b", "a", "b", "a", "b"];
        let err =
            prompt_new_password("alice", &mut scripted(&answers), &mut Vec::new()).unwrap_err();
        assert!(matches!(err, UsersError::PasswordMismatch));
    }

    #[test]
    fn prompt_rejects_empty_and_reports_tty_errors() {
        let err = prompt_new_password("a", &mut scripted(&[""]), &mut Vec::new()).unwrap_err();
        assert!(matches!(err, UsersError::InvalidPassword));
        let mut no_tty = Scripted(VecDeque::from([Err(io::Error::other("no tty"))]));
        let err = prompt_new_password("a", &mut no_tty, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("--password-stdin"), "{err}");
        let mut late = Scripted(VecDeque::from([Ok("pw"), Err(io::Error::other("closed"))]));
        assert!(matches!(
            prompt_new_password("a", &mut late, &mut Vec::new()),
            Err(UsersError::Prompt(_))
        ));
    }

    #[test]
    fn stdin_password_line() {
        assert_eq!(
            read_password_line(&mut &b"secret\r\n"[..])
                .unwrap()
                .as_str(),
            "secret"
        );
        assert!(matches!(
            read_password_line(&mut &b"\n"[..]),
            Err(UsersError::InvalidPassword)
        ));
        let long = "x".repeat(256);
        assert!(matches!(
            read_password_line(&mut long.as_bytes()),
            Err(UsersError::InvalidPassword)
        ));
        let mut bad = &[0xff, 0xfe, b'\n'][..];
        assert!(matches!(
            read_password_line(&mut bad),
            Err(UsersError::Io { .. })
        ));
    }
}
