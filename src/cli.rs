//! Command-line interface.

use std::ffi::OsStr;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use zeroize::Zeroizing;

use crate::Error;
use crate::config::Config;
use crate::paths;
use crate::users::{self, PasswordPrompt, Restart, UNIT, UsersFile};

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
        #[arg(short, long, default_value = paths::DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Manage users in the users file (usually needs sudo).
    User(UserArgs),
}

/// `rusty-sock user ...`
#[derive(Debug, Args)]
pub struct UserArgs {
    /// What to do.
    #[command(subcommand)]
    pub action: UserAction,
    /// Users file to edit [default: `auth.users_file` from the config, else
    /// /etc/rusty-sock/users].
    #[arg(long, global = true)]
    pub users_file: Option<PathBuf>,
    /// Config file used to locate the users file.
    #[arg(short, long, global = true, default_value = paths::DEFAULT_CONFIG)]
    pub config: PathBuf,
}

/// User management actions.
#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// Add a user; prompts for the password twice.
    Create {
        /// Username.
        name: String,
        /// Password and restart options.
        #[command(flatten)]
        opts: PasswordOpts,
    },
    /// Change a user's password; prompts for the password twice.
    Update {
        /// Username.
        name: String,
        /// Password and restart options.
        #[command(flatten)]
        opts: PasswordOpts,
    },
    /// Remove a user.
    Delete {
        /// Username.
        name: String,
        /// Restart the service (if running) so the change applies now.
        #[arg(long)]
        restart: bool,
    },
    /// List usernames (never hashes).
    List,
}

/// Options for actions that set a password.
#[derive(Debug, Args)]
pub struct PasswordOpts {
    /// Read the password from one line of stdin instead of prompting.
    #[arg(long)]
    pub password_stdin: bool,
    /// Restart the service (if running) so the change applies now.
    #[arg(long)]
    pub restart: bool,
}

/// I/O used by `user` commands, injectable for tests.
pub struct UserIo<'a> {
    /// Source for `--password-stdin`.
    pub stdin: &'a mut dyn BufRead,
    /// Where messages go.
    pub out: &'a mut dyn Write,
    /// Interactive, no-echo password prompt.
    pub prompt: &'a mut dyn PasswordPrompt,
    /// The `systemctl` program used by `--restart`.
    pub systemctl: &'a OsStr,
}

/// Run a `user` subcommand.
///
/// # Errors
/// Config, users file, prompt or restart errors.
pub fn run_user(args: &UserArgs, io: &mut UserIo<'_>) -> Result<(), Error> {
    let mut file = UsersFile::load(&users_file_path(args)?)?;
    let Some(change) = edit(&mut file, &args.action, io)? else {
        return Ok(());
    };
    file.save()?;
    report(&file, &change, io)?;
    apply(change.restart, io)
}

/// Apply `action` in memory; `None` for read-only actions.
fn edit<'a>(
    file: &mut UsersFile,
    action: &'a UserAction,
    io: &mut UserIo<'_>,
) -> Result<Option<Change<'a>>, Error> {
    match action {
        UserAction::List => list(file, io).map(|()| None),
        UserAction::Create { name, opts } => create(file, name, opts, io).map(Some),
        UserAction::Update { name, opts } => update(file, name, opts, io).map(Some),
        UserAction::Delete { name, restart } => delete(file, name, *restart).map(Some),
    }
}

fn report(file: &UsersFile, change: &Change<'_>, io: &mut UserIo<'_>) -> Result<(), Error> {
    let path = file.path().display();
    writeln!(io.out, "{} user `{}` in {path}", change.verb, change.name)?;
    Ok(())
}

/// A successful edit, reported after saving.
struct Change<'a> {
    verb: &'static str,
    name: &'a str,
    restart: bool,
}

fn list(file: &UsersFile, io: &mut UserIo<'_>) -> Result<(), Error> {
    for name in file.names() {
        writeln!(io.out, "{name}")?;
    }
    Ok(())
}

fn create<'a>(
    file: &mut UsersFile,
    name: &'a str,
    opts: &PasswordOpts,
    io: &mut UserIo<'_>,
) -> Result<Change<'a>, Error> {
    // Check before prompting so nobody types a password for nothing.
    file.ensure_absent(name)?;
    let hash = users::hash(&new_password(name, opts, io)?)?;
    file.create(name, hash)?;
    Ok(Change {
        verb: "created",
        name,
        restart: opts.restart,
    })
}

fn update<'a>(
    file: &mut UsersFile,
    name: &'a str,
    opts: &PasswordOpts,
    io: &mut UserIo<'_>,
) -> Result<Change<'a>, Error> {
    file.ensure_present(name)?;
    let hash = users::hash(&new_password(name, opts, io)?)?;
    file.update(name, hash)?;
    Ok(Change {
        verb: "updated",
        name,
        restart: opts.restart,
    })
}

fn delete<'a>(file: &mut UsersFile, name: &'a str, restart: bool) -> Result<Change<'a>, Error> {
    file.delete(name)?;
    Ok(Change {
        verb: "deleted",
        name,
        restart,
    })
}

fn users_file_path(args: &UserArgs) -> Result<PathBuf, Error> {
    if let Some(path) = &args.users_file {
        return Ok(path.clone());
    }
    if !args.config.exists() {
        return Ok(PathBuf::from(paths::DEFAULT_USERS));
    }
    // Never the systemd credentials copy: that is read-only runtime state.
    Ok(Config::load(&args.config)?.users_file(None))
}

fn new_password(
    name: &str,
    opts: &PasswordOpts,
    io: &mut UserIo<'_>,
) -> Result<Zeroizing<String>, Error> {
    let password = if opts.password_stdin {
        users::read_password_line(io.stdin)?
    } else {
        users::prompt_new_password(name, io.prompt, io.out)?
    };
    Ok(password)
}

fn apply(restart: bool, io: &mut UserIo<'_>) -> Result<(), Error> {
    let message = if restart {
        match users::restart_service(io.systemctl, UNIT)? {
            Restart::Restarted => "restarted rusty-sock",
            Restart::NotRunning => "rusty-sock is not running; changes apply when it starts",
        }
    } else {
        "restart to apply: sudo systemctl restart rusty-sock (or re-run with --restart)"
    };
    writeln!(io.out, "{message}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CredentialStore;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    /// Parses `user ...` arguments on their own, as the binary would.
    #[derive(Parser)]
    struct UserCli {
        #[command(flatten)]
        args: UserArgs,
    }

    /// Answers every prompt with the same password.
    struct Fixed(&'static str);

    impl PasswordPrompt for Fixed {
        fn prompt(&mut self, _: &str) -> std::io::Result<Zeroizing<String>> {
            Ok(Zeroizing::new(self.0.to_owned()))
        }
    }

    /// A temp users file plus a fake `systemctl` that reports "not running".
    struct Env {
        dir: tempfile::TempDir,
    }

    impl Env {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let stub = dir.path().join("systemctl");
            std::fs::write(&stub, "#!/bin/sh\n[ \"$1\" = try-restart ]\n").unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }

        fn users(&self) -> PathBuf {
            self.dir.path().join("users")
        }

        fn stub(&self) -> PathBuf {
            self.dir.path().join("systemctl")
        }

        /// Run `user <words> --users-file <users>`; returns result and output.
        fn run(
            &self,
            words: &[&str],
            stdin: &str,
            systemctl: &Path,
        ) -> (Result<(), Error>, String) {
            let users = self.users();
            let mut words: Vec<&str> = words.to_vec();
            words.extend(["--users-file", users.to_str().unwrap()]);
            let args = UserCli::try_parse_from(std::iter::once("user").chain(words))
                .unwrap()
                .args;
            let mut input = stdin.as_bytes();
            let mut out = Vec::new();
            let mut io = UserIo {
                stdin: &mut input,
                out: &mut out,
                prompt: &mut Fixed("prompted-pw"),
                systemctl: systemctl.as_os_str(),
            };
            let res = run_user(&args, &mut io);
            (res, String::from_utf8(out).unwrap())
        }

        fn verify(&self, user: &str, pass: &str) -> bool {
            let text = std::fs::read_to_string(self.users()).unwrap();
            CredentialStore::parse(&text)
                .unwrap()
                .verify(user.as_bytes(), pass.as_bytes())
        }
    }

    const TRUE: &str = "/bin/true";

    #[test]
    fn create_prompts_and_hints() {
        let env = Env::new();
        let (res, out) = env.run(&["create", "alice"], "", Path::new(TRUE));
        res.unwrap();
        assert!(out.contains("created user `alice`"), "{out}");
        assert!(out.contains("restart to apply"), "{out}");
        assert!(env.verify("alice", "prompted-pw"));
    }

    #[test]
    fn create_from_stdin_and_list() {
        let env = Env::new();
        env.run(&["create", "alice"], "", Path::new(TRUE))
            .0
            .unwrap();
        env.run(
            &["create", "bob", "--password-stdin"],
            "bob-pw\n",
            Path::new(TRUE),
        )
        .0
        .unwrap();
        assert!(env.verify("bob", "bob-pw"));
        let (res, out) = env.run(&["list"], "", Path::new(TRUE));
        res.unwrap();
        assert_eq!(out, "alice\nbob\n");
    }

    #[test]
    fn update_with_restart_when_not_running() {
        let env = Env::new();
        env.run(&["create", "alice"], "", Path::new(TRUE))
            .0
            .unwrap();
        let (res, out) = env.run(
            &["update", "alice", "--password-stdin", "--restart"],
            "new-pw\n",
            &env.stub(),
        );
        res.unwrap();
        assert!(out.contains("not running"), "{out}");
        assert!(env.verify("alice", "new-pw"));
        assert!(!env.verify("alice", "prompted-pw"));
    }

    #[test]
    fn delete_with_restart_when_running() {
        let env = Env::new();
        env.run(&["create", "alice"], "", Path::new(TRUE))
            .0
            .unwrap();
        let (res, out) = env.run(&["delete", "alice", "--restart"], "", Path::new(TRUE));
        res.unwrap();
        assert!(out.contains("restarted rusty-sock"), "{out}");
        assert!(!env.verify("alice", "prompted-pw"));
    }

    #[test]
    fn errors_happen_before_prompting() {
        let env = Env::new();
        let t = Path::new(TRUE);
        env.run(&["create", "alice"], "", t).0.unwrap();

        let (res, out) = env.run(&["create", "alice"], "", t);
        assert!(matches!(
            res,
            Err(Error::Users(users::UsersError::Exists(_)))
        ));
        assert_eq!(out, "", "no prompt output");

        let (res, _) = env.run(&["update", "zed"], "", t);
        assert!(matches!(
            res,
            Err(Error::Users(users::UsersError::NoSuchUser(_)))
        ));

        let (res, _) = env.run(&["update", "alice", "--password-stdin"], "\n", t);
        assert!(matches!(
            res,
            Err(Error::Users(users::UsersError::InvalidPassword))
        ));
        assert!(
            env.verify("alice", "prompted-pw"),
            "file unchanged on error"
        );
    }

    #[test]
    fn restart_failure_reports_saved_file() {
        let env = Env::new();
        let (res, out) = env.run(&["create", "a", "--restart"], "", Path::new("/bin/false"));
        let err = res.unwrap_err();
        assert!(err.to_string().contains("users file updated"), "{err}");
        assert!(out.contains("created user `a`"));
        assert!(env.verify("a", "prompted-pw"));
    }

    #[test]
    fn users_file_comes_from_config_or_default() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "[auth]\nusers_file = \"people\"\n").unwrap();
        let args = |c: &Path| UserArgs {
            action: UserAction::List,
            users_file: None,
            config: c.to_path_buf(),
        };
        assert_eq!(
            users_file_path(&args(&config)).unwrap(),
            dir.path().join("people")
        );
        assert_eq!(
            users_file_path(&args(&dir.path().join("missing.toml"))).unwrap(),
            PathBuf::from(paths::DEFAULT_USERS)
        );
        std::fs::write(&config, "bogus = 1\n").unwrap();
        assert!(matches!(
            users_file_path(&args(&config)),
            Err(Error::Config(_))
        ));
    }

    fn serve_config(words: &[&str]) -> Option<PathBuf> {
        match Cli::try_parse_from(words).unwrap().command {
            Command::Serve { config } => Some(config),
            Command::User(_) => None,
        }
    }

    #[test]
    fn parses_serve_args() {
        let explicit = serve_config(&["rusty-sock", "serve", "-c", "x.toml"]);
        assert_eq!(explicit, Some(PathBuf::from("x.toml")));
        let default = serve_config(&["rusty-sock", "serve"]);
        assert_eq!(default, Some(PathBuf::from(paths::DEFAULT_CONFIG)));
        assert_eq!(serve_config(&["rusty-sock", "user", "list"]), None);
    }

    #[test]
    fn parses_user_args() {
        let parsed = Cli::try_parse_from(["rusty-sock", "user", "list"]).unwrap();
        let listed = matches!(
            parsed.command,
            Command::User(UserArgs {
                action: UserAction::List,
                ..
            })
        );
        assert!(listed);
        assert!(Cli::try_parse_from(["rusty-sock", "hash-password"]).is_err());
        assert!(Cli::try_parse_from(["rusty-sock", "user", "create"]).is_err());
    }
}
