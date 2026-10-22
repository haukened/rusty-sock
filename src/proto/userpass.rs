//! Username/password sub-negotiation (RFC 1929).

use zeroize::Zeroizing;

use super::{Cursor, ProtoError};

/// Sub-negotiation version byte.
pub const VERSION: u8 = 0x01;
/// Status: success.
pub const STATUS_SUCCESS: u8 = 0x00;
/// Status: failure (any non-zero value).
pub const STATUS_FAILURE: u8 = 0x01;

/// Credentials sent by the client. The password is wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Username bytes.
    pub username: Vec<u8>,
    /// Password bytes.
    pub password: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Parse `VER | ULEN | UNAME | PLEN | PASSWD`.
///
/// # Errors
/// [`ProtoError::Incomplete`] if more bytes are needed,
/// [`ProtoError::BadVersion`] if `VER` is not 1, or
/// [`ProtoError::EmptyCredential`] if either field is empty.
pub fn parse(buf: &[u8]) -> Result<(Credentials, usize), ProtoError> {
    let mut c = Cursor::new(buf);
    let ver = c.u8()?;
    if ver != VERSION {
        return Err(ProtoError::BadVersion(ver));
    }
    let username = read_field(&mut c)?.to_vec();
    let password = Zeroizing::new(read_field(&mut c)?.to_vec());
    Ok((Credentials { username, password }, c.position()))
}

fn read_field<'a>(c: &mut Cursor<'a>) -> Result<&'a [u8], ProtoError> {
    let len = usize::from(c.u8()?);
    let field = c.take(len)?;
    if field.is_empty() {
        return Err(ProtoError::EmptyCredential);
    }
    Ok(field)
}

/// Encode the `VER | STATUS` response.
#[must_use]
pub fn encode_status(success: bool) -> [u8; 2] {
    let status = if success {
        STATUS_SUCCESS
    } else {
        STATUS_FAILURE
    };
    [VERSION, status]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn encode(user: &[u8], pass: &[u8]) -> Vec<u8> {
        let mut out = vec![VERSION, u8::try_from(user.len()).unwrap()];
        out.extend_from_slice(user);
        out.push(u8::try_from(pass.len()).unwrap());
        out.extend_from_slice(pass);
        out
    }

    #[test]
    fn parses_credentials() {
        let buf = encode(b"alice", b"s3cret");
        let (creds, n) = parse(&buf).unwrap();
        assert_eq!(creds.username, b"alice");
        assert_eq!(creds.password.as_slice(), b"s3cret");
        assert_eq!(n, buf.len());
    }

    #[test]
    fn debug_redacts_password() {
        let (creds, _) = parse(&encode(b"alice", b"s3cret")).unwrap();
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("alice"));
        assert!(!dbg.contains("s3cret"));
    }

    #[test]
    fn rejects_bad_version_and_empty_fields() {
        assert_eq!(
            parse(&[5, 1, b'a', 1, b'b']),
            Err(ProtoError::BadVersion(5))
        );
        assert_eq!(parse(&[1, 0, 1, b'b']), Err(ProtoError::EmptyCredential));
        assert_eq!(parse(&[1, 1, b'a', 0]), Err(ProtoError::EmptyCredential));
    }

    #[test]
    fn incomplete_credentials() {
        let buf = encode(b"alice", b"pw");
        for len in 0..buf.len() {
            assert_eq!(parse(&buf[..len]), Err(ProtoError::Incomplete), "len {len}");
        }
    }

    #[test]
    fn encodes_status() {
        assert_eq!(encode_status(true), [1, 0]);
        assert_eq!(encode_status(false), [1, 1]);
    }

    proptest! {
        #[test]
        fn round_trips(user in prop::collection::vec(any::<u8>(), 1..=255),
                       pass in prop::collection::vec(any::<u8>(), 1..=255)) {
            let (creds, n) = parse(&encode(&user, &pass)).unwrap();
            prop_assert_eq!(creds.username, user.clone());
            prop_assert_eq!(creds.password.as_slice(), pass.as_slice());
            prop_assert_eq!(n, 3 + user.len() + pass.len());
        }

        #[test]
        fn arbitrary_bytes_never_panic(buf: Vec<u8>) {
            let _ = parse(&buf);
        }
    }
}
