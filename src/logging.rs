//! Log output setup.
//!
//! Logs go to stdout. Colour codes are only used on a terminal, and
//! timestamps are left out under journald, which records its own.

use std::io::IsTerminal;

/// How log lines are formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Emit ANSI colour codes.
    pub ansi: bool,
    /// Prefix lines with a timestamp.
    pub timestamps: bool,
}

/// Pick a style from the output environment.
#[must_use]
pub fn style(is_tty: bool, under_journald: bool) -> Style {
    Style {
        ansi: is_tty,
        timestamps: !under_journald,
    }
}

/// Install the global subscriber. The level comes from `RUST_LOG`
/// (default `info`). Does nothing if a subscriber is already installed.
pub fn init() {
    init_with(style(
        std::io::stdout().is_terminal(),
        std::env::var_os("JOURNAL_STREAM").is_some(),
    ));
}

/// Install the global subscriber with an explicit style.
pub fn init_with(style: Style) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(style.ansi);
    let _ = if style.timestamps {
        builder.try_init()
    } else {
        builder.without_time().try_init()
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn style_matrix() {
        assert_eq!(
            style(true, false),
            Style {
                ansi: true,
                timestamps: true
            }
        );
        assert_eq!(
            style(false, false),
            Style {
                ansi: false,
                timestamps: true
            }
        );
        assert_eq!(
            style(false, true),
            Style {
                ansi: false,
                timestamps: false
            }
        );
    }

    #[test]
    fn init_is_idempotent() {
        init_with(Style {
            ansi: false,
            timestamps: false,
        });
        init_with(Style {
            ansi: false,
            timestamps: true,
        });
        init();
        tracing::info!("logging initialised");
    }
}
