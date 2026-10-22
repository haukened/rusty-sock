//! The opt-in `--restart`: apply users file changes to a running service.

use std::ffi::OsStr;
use std::process::Command;

use super::UsersError;

/// What `--restart` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// The service was running and has been restarted.
    Restarted,
    /// The service is not running; changes apply when it starts.
    NotRunning,
}

/// `systemctl try-restart <unit>`: restart only if running, never start it.
///
/// # Errors
/// [`UsersError::Restart`] if `systemctl` is missing or fails.
pub fn restart_service(systemctl: &OsStr, unit: &str) -> Result<Restart, UsersError> {
    let status = Command::new(systemctl)
        .args(["try-restart", unit])
        .status()
        .map_err(|e| UsersError::Restart(format!("cannot run systemctl: {e}")))?;
    if !status.success() {
        return Err(UsersError::Restart(format!(
            "systemctl try-restart {status}"
        )));
    }
    let active = Command::new(systemctl)
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success());
    Ok(if active {
        Restart::Restarted
    } else {
        Restart::NotRunning
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::UNIT;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn stub(dir: &Path, script: &str) -> PathBuf {
        let path = dir.join("systemctl");
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn restart_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let running = stub(dir.path(), "exit 0");
        assert_eq!(
            restart_service(running.as_os_str(), UNIT).unwrap(),
            Restart::Restarted
        );

        let dir2 = tempfile::tempdir().unwrap();
        let stopped = stub(dir2.path(), "[ \"$1\" = try-restart ]");
        assert_eq!(
            restart_service(stopped.as_os_str(), UNIT).unwrap(),
            Restart::NotRunning
        );

        let dir3 = tempfile::tempdir().unwrap();
        let failing = stub(dir3.path(), "exit 1");
        let err = restart_service(failing.as_os_str(), UNIT).unwrap_err();
        assert!(err.to_string().contains("users file updated"), "{err}");

        let err = restart_service(OsStr::new("/nonexistent/systemctl"), UNIT).unwrap_err();
        assert!(err.to_string().contains("cannot run systemctl"), "{err}");
    }
}
