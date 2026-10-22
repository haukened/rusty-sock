//! Sans-IO SOCKS5 wire format (RFC 1928) and username/password
//! sub-negotiation (RFC 1929).
//!
//! Every parser takes a byte slice and returns the decoded value together
//! with the number of bytes consumed, or [`ProtoError::Incomplete`] when more
//! input is required.

pub mod address;
pub mod greeting;
pub mod reply;
pub mod request;
pub mod udp;
pub mod userpass;

pub use address::TargetAddr;

/// A sans-IO parser: the decoded value and the number of bytes consumed.
pub type Parser<T> = fn(&[u8]) -> Result<(T, usize), ProtoError>;

/// SOCKS protocol version byte.
pub const VERSION: u8 = 0x05;

/// Authentication method codes (RFC 1928 §3).
pub mod method {
    /// No authentication required.
    pub const NO_AUTH: u8 = 0x00;
    /// Username/password (RFC 1929).
    pub const USER_PASS: u8 = 0x02;
    /// No acceptable methods.
    pub const NO_ACCEPTABLE: u8 = 0xFF;
}

/// Request commands (RFC 1928 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `CONNECT` (0x01).
    Connect,
    /// `BIND` (0x02).
    Bind,
    /// `UDP ASSOCIATE` (0x03).
    UdpAssociate,
}

impl TryFrom<u8> for Command {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            other => Err(ProtoError::UnsupportedCommand(other)),
        }
    }
}

/// Reply codes (RFC 1928 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rep {
    /// Succeeded.
    Succeeded = 0x00,
    /// General SOCKS server failure.
    GeneralFailure = 0x01,
    /// Connection not allowed by ruleset.
    NotAllowed = 0x02,
    /// Network unreachable.
    NetworkUnreachable = 0x03,
    /// Host unreachable.
    HostUnreachable = 0x04,
    /// Connection refused.
    ConnectionRefused = 0x05,
    /// TTL expired.
    TtlExpired = 0x06,
    /// Command not supported.
    CommandNotSupported = 0x07,
    /// Address type not supported.
    AddressTypeNotSupported = 0x08,
}

/// Errors produced while decoding protocol messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// More bytes are needed to decode the message.
    #[error("incomplete message")]
    Incomplete,
    /// The version byte did not match.
    #[error("unsupported version {0:#04x}")]
    BadVersion(u8),
    /// A reserved field was not zero.
    #[error("reserved field is not zero")]
    BadReserved,
    /// Unknown request command.
    #[error("unsupported command {0:#04x}")]
    UnsupportedCommand(u8),
    /// Unknown address type.
    #[error("unsupported address type {0:#04x}")]
    UnsupportedAddressType(u8),
    /// Domain name was empty or contained invalid characters.
    #[error("invalid domain name")]
    InvalidDomain,
    /// A username or password field was empty.
    #[error("empty credential field")]
    EmptyCredential,
    /// A fragmented UDP datagram was received (fragmentation is unsupported).
    #[error("fragmented datagram")]
    Fragmented,
}

impl ProtoError {
    /// The reply code to send when a request fails with this error.
    #[must_use]
    pub fn rep(&self) -> Rep {
        match self {
            Self::UnsupportedCommand(_) => Rep::CommandNotSupported,
            Self::UnsupportedAddressType(_) => Rep::AddressTypeNotSupported,
            Self::InvalidDomain => Rep::HostUnreachable,
            _ => Rep::GeneralFailure,
        }
    }
}

/// A forward-only reader over a byte slice.
#[derive(Debug)]
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::Incomplete)?;
        let slice = self.buf.get(self.pos..end).ok_or(ProtoError::Incomplete)?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn expect_u8(&mut self, value: u8, err: ProtoError) -> Result<(), ProtoError> {
        if self.u8()? == value {
            Ok(())
        } else {
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_from_u8() {
        assert_eq!(Command::try_from(1), Ok(Command::Connect));
        assert_eq!(Command::try_from(2), Ok(Command::Bind));
        assert_eq!(Command::try_from(3), Ok(Command::UdpAssociate));
        assert_eq!(Command::try_from(9), Err(ProtoError::UnsupportedCommand(9)));
    }

    #[test]
    fn error_to_rep() {
        assert_eq!(
            ProtoError::UnsupportedCommand(9).rep(),
            Rep::CommandNotSupported
        );
        assert_eq!(
            ProtoError::UnsupportedAddressType(9).rep(),
            Rep::AddressTypeNotSupported
        );
        assert_eq!(ProtoError::InvalidDomain.rep(), Rep::HostUnreachable);
        assert_eq!(ProtoError::BadReserved.rep(), Rep::GeneralFailure);
    }

    #[test]
    fn cursor_reads_and_bounds() {
        let mut c = Cursor::new(&[1, 0x12, 0x34]);
        assert_eq!(c.u8(), Ok(1));
        assert_eq!(c.u16(), Ok(0x1234));
        assert_eq!(c.position(), 3);
        assert_eq!(c.u8(), Err(ProtoError::Incomplete));
        assert_eq!(c.take(usize::MAX), Err(ProtoError::Incomplete));
    }

    #[test]
    fn cursor_expect() {
        let mut c = Cursor::new(&[5, 4]);
        assert_eq!(c.expect_u8(5, ProtoError::BadReserved), Ok(()));
        assert_eq!(
            c.expect_u8(5, ProtoError::BadReserved),
            Err(ProtoError::BadReserved)
        );
    }
}
