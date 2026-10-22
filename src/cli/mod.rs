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
mod tests;
