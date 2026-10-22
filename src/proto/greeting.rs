//! Method negotiation (RFC 1928 §3).

use super::{Cursor, ProtoError, VERSION, method};

/// The client's greeting: the list of offered authentication methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    /// Offered method codes.
    pub methods: Vec<u8>,
}

/// Parse `VER | NMETHODS | METHODS`.
///
/// # Errors
/// [`ProtoError::Incomplete`] if more bytes are needed, or
/// [`ProtoError::BadVersion`] if `VER` is not 5.
pub fn parse(buf: &[u8]) -> Result<(Greeting, usize), ProtoError> {
    let mut c = Cursor::new(buf);
    let ver = c.u8()?;
    if ver != VERSION {
        return Err(ProtoError::BadVersion(ver));
    }
    let n = usize::from(c.u8()?);
    let methods = c.take(n)?.to_vec();
    Ok((Greeting { methods }, c.position()))
}

/// Pick the first method in the server's preference order that the client
/// offered, or [`method::NO_ACCEPTABLE`].
#[must_use]
pub fn select_method(offered: &[u8], supported: &[u8]) -> u8 {
    supported
        .iter()
        .copied()
        .find(|m| offered.contains(m))
        .unwrap_or(method::NO_ACCEPTABLE)
}

/// Encode the server's `VER | METHOD` selection.
#[must_use]
pub fn encode_choice(method: u8) -> [u8; 2] {
    [VERSION, method]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_greeting() {
        let (g, n) = parse(&[5, 2, 0, 2, 0xAA]).unwrap();
        assert_eq!(g.methods, vec![0, 2]);
        assert_eq!(n, 4);
    }

    #[test]
    fn parses_empty_method_list() {
        let (g, n) = parse(&[5, 0]).unwrap();
        assert_eq!(g.methods, [] as [u8; 0]);
        assert_eq!(n, 2);
    }

    #[test]
    fn rejects_wrong_version() {
        assert_eq!(parse(&[4, 1, 0]), Err(ProtoError::BadVersion(4)));
    }

    #[test]
    fn incomplete_greeting() {
        assert_eq!(parse(&[]), Err(ProtoError::Incomplete));
        assert_eq!(parse(&[5]), Err(ProtoError::Incomplete));
        assert_eq!(parse(&[5, 2, 0]), Err(ProtoError::Incomplete));
    }

    #[test]
    fn selection_matrix() {
        use method::{NO_ACCEPTABLE, NO_AUTH, USER_PASS};
        assert_eq!(
            select_method(&[NO_AUTH, USER_PASS], &[USER_PASS]),
            USER_PASS
        );
        assert_eq!(select_method(&[NO_AUTH], &[USER_PASS]), NO_ACCEPTABLE);
        assert_eq!(select_method(&[NO_AUTH, USER_PASS], &[NO_AUTH]), NO_AUTH);
        assert_eq!(select_method(&[USER_PASS], &[NO_AUTH]), NO_ACCEPTABLE);
        assert_eq!(select_method(&[], &[NO_AUTH]), NO_ACCEPTABLE);
        assert_eq!(select_method(&[0x01, 0x80], &[USER_PASS]), NO_ACCEPTABLE);
    }

    #[test]
    fn encodes_choice() {
        assert_eq!(encode_choice(2), [5, 2]);
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(buf: Vec<u8>) {
            let _ = parse(&buf);
        }
    }
}
