//! Errors raised while establishing outbound connections, and their mapping
//! to SOCKS reply codes.

use std::io;

use crate::policy::Denied;
use crate::proto::Rep;

/// Why an outbound connection (or datagram destination) could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// The egress policy refused the destination.
    #[error("destination denied: {0}")]
    Denied(#[from] Denied),
    /// DNS resolution failed.
    #[error("resolution failed: {0}")]
    Resolve(io::Error),
    /// The name resolved to no addresses.
    #[error("name resolved to no addresses")]
    NoAddresses,
    /// The operation did not finish in time.
    #[error("timed out")]
    Timeout,
    /// Connecting failed.
    #[error("connect failed: {0}")]
    Io(#[from] io::Error),
}

impl ConnectError {
    /// The reply code to report to the client.
    #[must_use]
    pub fn rep(&self) -> Rep {
        match self {
            Self::Denied(_) => Rep::NotAllowed,
            Self::Resolve(_) | Self::NoAddresses | Self::Timeout => Rep::HostUnreachable,
            Self::Io(e) => io_rep(e.kind()),
        }
    }
}

fn io_rep(kind: io::ErrorKind) -> Rep {
    match kind {
        io::ErrorKind::ConnectionRefused => Rep::ConnectionRefused,
        io::ErrorKind::NetworkUnreachable => Rep::NetworkUnreachable,
        io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut => Rep::HostUnreachable,
        _ => Rep::GeneralFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_err(kind: io::ErrorKind) -> ConnectError {
        ConnectError::Io(io::Error::from(kind))
    }

    #[test]
    fn maps_to_reply_codes() {
        use io::ErrorKind as K;
        assert_eq!(ConnectError::from(Denied::Port).rep(), Rep::NotAllowed);
        assert_eq!(
            ConnectError::Resolve(io::Error::other("x")).rep(),
            Rep::HostUnreachable
        );
        assert_eq!(ConnectError::NoAddresses.rep(), Rep::HostUnreachable);
        assert_eq!(ConnectError::Timeout.rep(), Rep::HostUnreachable);
        assert_eq!(io_err(K::ConnectionRefused).rep(), Rep::ConnectionRefused);
        assert_eq!(io_err(K::NetworkUnreachable).rep(), Rep::NetworkUnreachable);
        assert_eq!(io_err(K::HostUnreachable).rep(), Rep::HostUnreachable);
        assert_eq!(io_err(K::TimedOut).rep(), Rep::HostUnreachable);
        assert_eq!(io_err(K::PermissionDenied).rep(), Rep::GeneralFailure);
    }
}
