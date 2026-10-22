//! Address encoding shared by requests, replies and UDP headers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{Cursor, ProtoError};

/// Address type: IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// A destination as sent by the client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    /// A literal IP address and port.
    Ip(SocketAddr),
    /// A domain name to be resolved by the server, and a port.
    Domain(String, u16),
}

impl TargetAddr {
    /// The destination port.
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    pub(crate) fn read(c: &mut Cursor<'_>) -> Result<Self, ProtoError> {
        let atyp = c.u8()?;
        let addr = match atyp {
            ATYP_IPV4 => Self::read_ipv4(c)?,
            ATYP_IPV6 => Self::read_ipv6(c)?,
            ATYP_DOMAIN => Self::read_domain(c)?,
            other => return Err(ProtoError::UnsupportedAddressType(other)),
        };
        Ok(addr)
    }

    fn read_ipv4(c: &mut Cursor<'_>) -> Result<Self, ProtoError> {
        let ip = IpAddr::V4(Ipv4Addr::from(c.array::<4>()?));
        Ok(Self::Ip(SocketAddr::new(ip, c.u16()?)))
    }

    fn read_ipv6(c: &mut Cursor<'_>) -> Result<Self, ProtoError> {
        let ip = IpAddr::V6(Ipv6Addr::from(c.array::<16>()?));
        Ok(Self::Ip(SocketAddr::new(ip, c.u16()?)))
    }

    fn read_domain(c: &mut Cursor<'_>) -> Result<Self, ProtoError> {
        let len = usize::from(c.u8()?);
        let raw = c.take(len)?;
        let port = c.u16()?;
        let name = validate_domain(raw)?;
        Ok(Self::Domain(name, port))
    }

    /// Append the `ATYP | ADDR | PORT` encoding to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Ip(addr) => write_socket_addr(*addr, out),
            Self::Domain(name, port) => {
                out.push(ATYP_DOMAIN);
                // Names are validated to at most 255 bytes on input; clamp
                // defensively for values constructed elsewhere.
                let bytes = &name.as_bytes()[..name.len().min(255)];
                out.push(u8::try_from(bytes.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(bytes);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

/// Append the `ATYP | ADDR | PORT` encoding of a socket address to `out`.
pub fn write_socket_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Accept only non-empty hostnames made of letters, digits, `-`, `_` and `.`.
fn validate_domain(raw: &[u8]) -> Result<String, ProtoError> {
    let valid = !raw.is_empty()
        && raw
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if !valid {
        return Err(ProtoError::InvalidDomain);
    }
    String::from_utf8(raw.to_vec()).map_err(|_| ProtoError::InvalidDomain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parse(buf: &[u8]) -> Result<TargetAddr, ProtoError> {
        TargetAddr::read(&mut Cursor::new(buf))
    }

    fn encode(addr: &TargetAddr) -> Vec<u8> {
        let mut out = Vec::new();
        addr.write(&mut out);
        out
    }

    #[test]
    fn ipv4_round_trip() {
        let buf = [ATYP_IPV4, 10, 0, 0, 1, 0x1F, 0x90];
        let addr = parse(&buf).unwrap();
        assert_eq!(addr, TargetAddr::Ip("10.0.0.1:8080".parse().unwrap()));
        assert_eq!(addr.port(), 8080);
        assert_eq!(encode(&addr), buf);
    }

    #[test]
    fn ipv6_round_trip() {
        let addr = TargetAddr::from("[2001:db8::1]:443".parse::<SocketAddr>().unwrap());
        let buf = encode(&addr);
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
        assert_eq!(parse(&buf).unwrap(), addr);
    }

    #[test]
    fn domain_round_trip() {
        let addr = TargetAddr::Domain("example.com".into(), 443);
        let buf = encode(&addr);
        assert_eq!(&buf[..2], &[ATYP_DOMAIN, 11]);
        assert_eq!(parse(&buf).unwrap(), addr);
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn domain_max_length() {
        let name = "a".repeat(255);
        let addr = TargetAddr::Domain(name.clone(), 1);
        assert_eq!(parse(&encode(&addr)).unwrap(), addr);
        let too_long = TargetAddr::Domain("a".repeat(300), 1);
        let buf = encode(&too_long);
        assert_eq!(buf[1], 255);
        assert_eq!(parse(&buf).unwrap(), TargetAddr::Domain(name, 1));
    }

    #[test]
    fn rejects_bad_domains() {
        assert_eq!(
            parse(&[ATYP_DOMAIN, 0, 0, 80]),
            Err(ProtoError::InvalidDomain)
        );
        assert_eq!(
            parse(&[ATYP_DOMAIN, 3, b'a', 0, b'b', 0, 80]),
            Err(ProtoError::InvalidDomain)
        );
        assert_eq!(
            parse(&[ATYP_DOMAIN, 2, 0xC3, 0xA9, 0, 80]),
            Err(ProtoError::InvalidDomain)
        );
    }

    #[test]
    fn rejects_unknown_atyp() {
        assert_eq!(parse(&[0x02]), Err(ProtoError::UnsupportedAddressType(2)));
    }

    #[test]
    fn truncated_inputs_are_incomplete() {
        for buf in [
            &[][..],
            &[ATYP_IPV4, 1, 2][..],
            &[ATYP_IPV4, 1, 2, 3, 4, 0][..],
            &[ATYP_IPV6, 0][..],
            &[ATYP_DOMAIN][..],
            &[ATYP_DOMAIN, 3, b'a'][..],
            &[ATYP_DOMAIN, 1, b'a', 0][..],
        ] {
            assert_eq!(parse(buf), Err(ProtoError::Incomplete), "{buf:?}");
        }
    }

    proptest! {
        #[test]
        fn socket_addr_round_trips(ip: std::net::IpAddr, port: u16) {
            let addr = SocketAddr::new(ip, port);
            let target = TargetAddr::Ip(addr);
            prop_assert_eq!(parse(&encode(&target)).unwrap(), target);
        }

        #[test]
        fn domain_round_trips(name in "[a-zA-Z0-9._-]{1,255}", port: u16) {
            let target = TargetAddr::Domain(name, port);
            prop_assert_eq!(parse(&encode(&target)).unwrap(), target);
        }

        #[test]
        fn arbitrary_bytes_never_panic(buf: Vec<u8>) {
            let _ = parse(&buf);
        }
    }
}
