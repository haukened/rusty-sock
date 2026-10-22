//! UDP relay datagram header (RFC 1928 §7).

use super::{Cursor, ProtoError, TargetAddr};

/// Parse `RSV(2) | FRAG | ATYP | DST.ADDR | DST.PORT` and return the target
/// together with the offset of `DATA`.
///
/// # Errors
/// [`ProtoError::BadReserved`] if `RSV` is non-zero,
/// [`ProtoError::Fragmented`] if `FRAG` is non-zero (fragmentation is not
/// supported, so such datagrams must be dropped), or an address error.
pub fn parse(buf: &[u8]) -> Result<(TargetAddr, usize), ProtoError> {
    let mut c = Cursor::new(buf);
    if c.u16()? != 0 {
        return Err(ProtoError::BadReserved);
    }
    c.expect_u8(0, ProtoError::Fragmented)?;
    let target = TargetAddr::read(&mut c)?;
    Ok((target, c.position()))
}

/// Encode a datagram: header for `source` followed by `payload`.
#[must_use]
pub fn encode(source: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    source.write(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::SocketAddr;

    #[test]
    fn parses_header_and_payload() {
        let target = TargetAddr::Ip("8.8.8.8:53".parse().unwrap());
        let dgram = encode(&target, b"query");
        let (parsed, off) = parse(&dgram).unwrap();
        assert_eq!(parsed, target);
        assert_eq!(&dgram[off..], b"query");
    }

    #[test]
    fn rejects_reserved_and_fragments() {
        assert_eq!(parse(&[0, 1, 0, 1]), Err(ProtoError::BadReserved));
        assert_eq!(parse(&[0, 0, 1, 1]), Err(ProtoError::Fragmented));
        assert_eq!(parse(&[0, 0, 0x81, 1]), Err(ProtoError::Fragmented));
    }

    #[test]
    fn incomplete_header() {
        assert_eq!(parse(&[0]), Err(ProtoError::Incomplete));
        assert_eq!(parse(&[0, 0]), Err(ProtoError::Incomplete));
        assert_eq!(parse(&[0, 0, 0, 1, 1]), Err(ProtoError::Incomplete));
    }

    proptest! {
        #[test]
        fn round_trips(ip: std::net::IpAddr, port: u16, payload: Vec<u8>) {
            let addr = SocketAddr::new(ip, port);
            let target = TargetAddr::Ip(addr);
            let dgram = encode(&target, &payload);
            let (parsed, off) = parse(&dgram).unwrap();
            prop_assert_eq!(parsed, target);
            prop_assert_eq!(&dgram[off..], payload.as_slice());
        }

        #[test]
        fn arbitrary_bytes_never_panic(buf: Vec<u8>) {
            let _ = parse(&buf);
        }
    }
}
