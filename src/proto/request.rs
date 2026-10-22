//! Client requests (RFC 1928 §4).

use super::{Command, Cursor, ProtoError, TargetAddr, VERSION};

/// A decoded client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The requested command.
    pub command: Command,
    /// The destination address (or, for UDP ASSOCIATE, the client's
    /// expected source address).
    pub target: TargetAddr,
}

/// Parse `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`.
///
/// # Errors
/// [`ProtoError::Incomplete`] if more bytes are needed; otherwise the
/// first violation found in field order.
pub fn parse(buf: &[u8]) -> Result<(Request, usize), ProtoError> {
    let mut c = Cursor::new(buf);
    let ver = c.u8()?;
    if ver != VERSION {
        return Err(ProtoError::BadVersion(ver));
    }
    let command = Command::try_from(c.u8()?)?;
    c.expect_u8(0, ProtoError::BadReserved)?;
    let target = TargetAddr::read(&mut c)?;
    Ok((Request { command, target }, c.position()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_connect_ipv4() {
        let buf = [5, 1, 0, 1, 93, 184, 216, 34, 0, 80];
        let (req, n) = parse(&buf).unwrap();
        assert_eq!(req.command, Command::Connect);
        assert_eq!(
            req.target,
            TargetAddr::Ip("93.184.216.34:80".parse().unwrap())
        );
        assert_eq!(n, buf.len());
    }

    #[test]
    fn parses_each_command() {
        for (code, cmd) in [
            (1, Command::Connect),
            (2, Command::Bind),
            (3, Command::UdpAssociate),
        ] {
            let (req, _) = parse(&[5, code, 0, 3, 1, b'a', 0, 53]).unwrap();
            assert_eq!(req.command, cmd);
            assert_eq!(req.target, TargetAddr::Domain("a".into(), 53));
        }
    }

    #[test]
    fn rejects_violations() {
        assert_eq!(parse(&[4, 1, 0, 1]), Err(ProtoError::BadVersion(4)));
        assert_eq!(parse(&[5, 9, 0, 1]), Err(ProtoError::UnsupportedCommand(9)));
        assert_eq!(parse(&[5, 1, 1, 1]), Err(ProtoError::BadReserved));
        assert_eq!(
            parse(&[5, 1, 0, 7]),
            Err(ProtoError::UnsupportedAddressType(7))
        );
    }

    #[test]
    fn incomplete_request() {
        let buf = [5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
        for len in 0..buf.len() {
            assert_eq!(parse(&buf[..len]), Err(ProtoError::Incomplete), "len {len}");
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(buf: Vec<u8>) {
            let _ = parse(&buf);
        }
    }
}
