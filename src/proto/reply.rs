//! Server replies (RFC 1928 §6).

use std::net::{Ipv4Addr, SocketAddr};

use super::{Rep, VERSION, address::write_socket_addr};

/// The bound address sent with failure replies.
pub const UNSPECIFIED: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Encode `VER | REP | RSV | ATYP | BND.ADDR | BND.PORT`.
#[must_use]
pub fn encode(rep: Rep, bound: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(&[VERSION, rep as u8, 0x00]);
    write_socket_addr(bound, &mut out);
    out
}

/// Encode a failure reply with an unspecified bound address.
#[must_use]
pub fn encode_failure(rep: Rep) -> Vec<u8> {
    encode(rep, UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Cursor, TargetAddr};
    use proptest::prelude::*;

    #[test]
    fn encodes_success_ipv4() {
        let out = encode(Rep::Succeeded, "127.0.0.1:1080".parse().unwrap());
        assert_eq!(out, [5, 0, 0, 1, 127, 0, 0, 1, 0x04, 0x38]);
    }

    #[test]
    fn encodes_failure() {
        assert_eq!(
            encode_failure(Rep::CommandNotSupported),
            [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    proptest! {
        #[test]
        fn bound_address_round_trips(ip: std::net::IpAddr, port: u16) {
            let addr = SocketAddr::new(ip, port);
            let out = encode(Rep::Succeeded, addr);
            let parsed = TargetAddr::read(&mut Cursor::new(&out[3..])).unwrap();
            prop_assert_eq!(parsed, TargetAddr::Ip(addr));
        }
    }
}
