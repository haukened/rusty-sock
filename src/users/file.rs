//! Line-preserving, atomic editing of the users file.
//!
//! Edits keep comments, blank lines and ordering. The file is replaced
//! atomically (temp file in the same directory, fsync, rename) and keeps its
//! owner and mode; new files are created `0600`.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{UsersError, io_error, validate_name};
use crate::auth::split_entry;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Entry { name: String, hash: String },
    Other(String),
}

/// An editable users file.
#[derive(Debug)]
pub struct UsersFile {
    path: PathBuf,
    lines: Vec<Line>,
    exists: bool,
}

impl UsersFile {
    /// Load `path`, or start empty if it does not exist.
    ///
    /// # Errors
    /// I/O errors, or [`UsersError::Malformed`] if any line is invalid.
    pub fn load(path: &Path) -> Result<Self, UsersError> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_path_buf(),
                    lines: Vec::new(),
                    exists: false,
                });
            }
            Err(e) => return Err(io_error(path, e)),
        };
        let lines = text
            .lines()
            .enumerate()
            .map(|(idx, raw)| parse_line(raw).map_err(|reason| malformed(path, idx, reason)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            path: path.to_path_buf(),
            lines,
            exists: true,
        })
    }

    /// The file this edits.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Usernames, in file order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().filter_map(|line| match line {
            Line::Entry { name, .. } => Some(name.as_str()),
            Line::Other(_) => None,
        })
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.lines
            .iter()
            .position(|l| matches!(l, Line::Entry { name: n, .. } if n == name))
    }

    /// Add a new user.
    ///
    /// # Errors
    /// [`UsersError::InvalidName`] or [`UsersError::Exists`].
    pub fn create(&mut self, name: &str, hash: String) -> Result<(), UsersError> {
        self.ensure_absent(name)?;
        self.lines.push(Line::Entry {
            name: name.to_owned(),
            hash,
        });
        Ok(())
    }

    /// Replace an existing user's hash.
    ///
    /// # Errors
    /// [`UsersError::NoSuchUser`].
    pub fn update(&mut self, name: &str, hash: String) -> Result<(), UsersError> {
        let idx = self.ensure_present(name)?;
        self.lines[idx] = Line::Entry {
            name: name.to_owned(),
            hash,
        };
        Ok(())
    }

    /// Remove a user.
    ///
    /// # Errors
    /// [`UsersError::NoSuchUser`].
    pub fn delete(&mut self, name: &str) -> Result<(), UsersError> {
        let idx = self.ensure_present(name)?;
        self.lines.remove(idx);
        Ok(())
    }

    /// Check that `name` is valid and not yet present (before prompting).
    ///
    /// # Errors
    /// [`UsersError::InvalidName`] or [`UsersError::Exists`].
    pub fn ensure_absent(&self, name: &str) -> Result<(), UsersError> {
        validate_name(name)?;
        match self.position(name) {
            Some(_) => Err(UsersError::Exists(name.to_owned())),
            None => Ok(()),
        }
    }

    /// Check that `name` exists and return its line index.
    ///
    /// # Errors
    /// [`UsersError::MissingFile`] or [`UsersError::NoSuchUser`].
    pub fn ensure_present(&self, name: &str) -> Result<usize, UsersError> {
        if !self.exists {
            return Err(UsersError::MissingFile(self.path.clone()));
        }
        self.position(name)
            .ok_or_else(|| UsersError::NoSuchUser(name.to_owned()))
    }

    /// The file contents.
    #[must_use]
    pub fn render(&self) -> String {
        self.lines
            .iter()
            .map(|line| match line {
                Line::Entry { name, hash } => format!("{name}:{hash}\n"),
                Line::Other(text) => format!("{text}\n"),
            })
            .collect()
    }

    /// Atomically replace the file, keeping its owner and mode.
    ///
    /// # Errors
    /// [`UsersError::Locked`] if a temp file from another edit exists, or
    /// I/O errors. The original file is untouched on failure.
    pub fn save(&self) -> Result<(), UsersError> {
        let (dir, tmp) = temp_path(&self.path);
        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(UsersError::Locked(tmp));
            }
            Err(e) => return Err(io_error(&tmp, e)),
        };
        let result = self.write_replace(file, &tmp, &dir);
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    fn write_replace(&self, mut file: File, tmp: &Path, dir: &Path) -> Result<(), UsersError> {
        file.write_all(self.render().as_bytes())
            .and_then(|()| self.copy_ownership(&file))
            .and_then(|()| file.sync_all())
            .map_err(|e| io_error(tmp, e))?;
        drop(file);
        fs::rename(tmp, &self.path).map_err(|e| io_error(&self.path, e))?;
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| io_error(dir, e))
    }

    /// Give the new file the original's owner and mode (new files: 0600).
    fn copy_ownership(&self, file: &File) -> io::Result<()> {
        let Ok(meta) = fs::metadata(&self.path) else {
            return Ok(());
        };
        std::os::unix::fs::fchown(file, Some(meta.uid()), Some(meta.gid()))?;
        file.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777))
    }
}

/// The directory holding `path` and the temp file used to replace it.
fn temp_path(path: &Path) -> (PathBuf, PathBuf) {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let file_name = path.file_name().unwrap_or(OsStr::new("users"));
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    (dir, tmp)
}

fn parse_line(raw: &str) -> Result<Line, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(Line::Other(raw.to_owned()));
    }
    let (name, hash) = split_entry(trimmed)?;
    Ok(Line::Entry {
        name: name.to_owned(),
        hash: hash.to_owned(),
    })
}

fn malformed(path: &Path, idx: usize, reason: &'static str) -> UsersError {
    UsersError::Malformed {
        path: path.to_path_buf(),
        line: idx + 1,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CredentialStore;
    use crate::users::hash;
    use std::sync::LazyLock;

    static HASH_A: LazyLock<String> = LazyLock::new(|| hash("alpha-pass").unwrap());
    static HASH_B: LazyLock<String> = LazyLock::new(|| hash("bravo-pass").unwrap());

    fn sample(dir: &Path) -> PathBuf {
        let path = dir.join("users");
        fs::write(
            &path,
            format!(
                "# header comment\n\nalpha:{}\n  # indented comment\nbravo:{}\n",
                *HASH_A, *HASH_B
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        path
    }

    /// Apply create/update/delete to the sample file and return its new text.
    fn edited(dir: &Path) -> (PathBuf, String) {
        let path = sample(dir);
        let mut f = UsersFile::load(&path).unwrap();
        assert_eq!(f.path(), path);
        assert_eq!(f.names().collect::<Vec<_>>(), ["alpha", "bravo"]);
        f.create("charlie", HASH_A.clone()).unwrap();
        f.update("alpha", HASH_B.clone()).unwrap();
        f.delete("bravo").unwrap();
        f.save().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        (path, text)
    }

    #[test]
    fn edits_keep_comments_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let (_, text) = edited(dir.path());
        let expected = [
            "# header comment".to_owned(),
            String::new(),
            format!("alpha:{}", *HASH_B),
            "  # indented comment".to_owned(),
            format!("charlie:{}", *HASH_A),
        ];
        assert_eq!(text.lines().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn edited_file_is_accepted_by_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let (_, text) = edited(dir.path());
        let store = CredentialStore::parse(&text).unwrap();
        assert!(store.verify(b"alpha", b"bravo-pass"));
        assert!(store.verify(b"charlie", b"alpha-pass"));
        assert!(!store.verify(b"bravo", b"bravo-pass"));
    }

    #[test]
    fn edits_keep_mode_and_clean_up() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = edited(dir.path());
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "existing mode is preserved");
        assert!(!dir.path().join(".users.tmp").exists());
    }

    #[test]
    fn new_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users");
        let mut f = UsersFile::load(&path).unwrap();
        assert_eq!(f.names().count(), 0);
        f.create("alpha", HASH_A.clone()).unwrap();
        f.save().unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn duplicate_and_unknown_users() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = UsersFile::load(&sample(dir.path())).unwrap();
        let dup = f.create("alpha", HASH_A.clone());
        assert!(matches!(dup, Err(UsersError::Exists(_))));
        let upd = f.update("zulu", HASH_A.clone());
        assert!(matches!(upd, Err(UsersError::NoSuchUser(_))));
        assert!(matches!(f.delete("zulu"), Err(UsersError::NoSuchUser(_))));
    }

    #[test]
    fn missing_file_only_allows_create() {
        let dir = tempfile::tempdir().unwrap();
        let mut missing = UsersFile::load(&dir.path().join("nope")).unwrap();
        let upd = missing.update("a", HASH_A.clone());
        assert!(matches!(upd, Err(UsersError::MissingFile(_))));
        assert!(matches!(
            missing.delete("a"),
            Err(UsersError::MissingFile(_))
        ));
    }

    #[test]
    fn refuses_to_edit_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users");
        fs::write(&path, "# ok\nnot-a-valid-line\n").unwrap();
        let err = UsersFile::load(&path).unwrap_err();
        assert!(
            matches!(err, UsersError::Malformed { line: 2, .. }),
            "{err}"
        );
    }

    #[test]
    fn load_io_error_suggests_sudo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("users");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        // Root can read anything, so there may be no error to check.
        let message = UsersFile::load(&path)
            .err()
            .map_or_else(|| "(try again with sudo)".to_owned(), |e| e.to_string());
        assert!(message.ends_with("(try again with sudo)"), "{message}");
        // A directory is not readable as a file: a non-permission I/O error.
        let err = UsersFile::load(dir.path()).unwrap_err();
        assert!(matches!(err, UsersError::Io { hint: "", .. }), "{err}");
    }

    #[test]
    fn save_is_locked_by_leftover_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = sample(dir.path());
        let before = fs::read_to_string(&path).unwrap();
        fs::write(dir.path().join(".users.tmp"), "").unwrap();
        let mut f = UsersFile::load(&path).unwrap();
        f.delete("alpha").unwrap();
        assert!(matches!(f.save(), Err(UsersError::Locked(_))));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            before,
            "original untouched"
        );
    }

    #[test]
    fn failed_rename_cleans_up_and_keeps_original() {
        let dir = tempfile::tempdir().unwrap();
        // The target is a non-empty directory, so the final rename fails.
        let target = dir.path().join("users");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), "x").unwrap();
        let f = UsersFile {
            path: target.clone(),
            lines: vec![Line::Other("# x".into())],
            exists: true,
        };
        assert!(matches!(f.save(), Err(UsersError::Io { .. })));
        assert!(target.join("keep").exists());
        assert!(!dir.path().join(".users.tmp").exists(), "temp file removed");
    }

    #[test]
    fn save_reports_unwritable_directory() {
        let f = UsersFile {
            path: PathBuf::from("/nonexistent-dir/users"),
            lines: Vec::new(),
            exists: false,
        };
        assert!(matches!(f.save(), Err(UsersError::Io { .. })));
    }

    #[test]
    fn temp_file_sits_next_to_target() {
        let p = |s: &str| PathBuf::from(s);
        assert_eq!(
            temp_path(Path::new("/etc/rusty-sock/users")),
            (p("/etc/rusty-sock"), p("/etc/rusty-sock/.users.tmp"))
        );
        assert_eq!(temp_path(Path::new("users")), (p("."), p("./.users.tmp")));
        assert_eq!(temp_path(Path::new("/")), (p("."), p("./.users.tmp")));
    }
}
