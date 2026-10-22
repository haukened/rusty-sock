//! Per-connection SOCKS5 state machine:
//! negotiate → authenticate → request → dispatch.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::CredentialStore;
use crate::config::Timeouts;
use crate::connector::{Connect, Stream};
use crate::error::ConnectError;
use crate::policy::EgressPolicy;
use crate::proto::request::Request;
use crate::proto::{Command, Parser, ProtoError, Rep, greeting, method, reply, request, userpass};
use crate::relay;
use crate::resolver::Resolve;

/// How clients authenticate.
#[derive(Debug, Clone)]
pub enum Authenticator {
    /// No authentication.
    None,
    /// Username/password against a credential store.
    Password(Arc<CredentialStore>),
}

impl Authenticator {
    /// Methods offered, in order of preference.
    #[must_use]
    pub fn methods(&self) -> &'static [u8] {
        match self {
            Self::None => &[method::NO_AUTH],
            Self::Password(_) => &[method::USER_PASS],
        }
    }
}

/// Shared, immutable state for all sessions.
pub struct Ctx {
    /// Client authentication.
    pub auth: Authenticator,
    /// Destination filter.
    pub policy: EgressPolicy,
    /// Hostname resolver.
    pub resolver: Arc<dyn Resolve>,
    /// Outbound connector.
    pub connector: Arc<dyn Connect>,
    /// Timeouts.
    pub timeouts: Timeouts,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx")
            .field("auth", &self.auth)
            .field("policy", &self.policy)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

/// Why a session ended abnormally.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Socket I/O failed.
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    /// The client sent a malformed message.
    #[error("protocol: {0}")]
    Proto(#[from] ProtoError),
    /// The client offered no acceptable authentication method.
    #[error("no acceptable authentication method")]
    NoAcceptableMethod,
    /// Authentication failed.
    #[error("authentication failed")]
    AuthFailed,
    /// The handshake did not complete in time.
    #[error("handshake timed out")]
    Timeout,
    /// The requested command is not supported.
    #[error("command not supported")]
    UnsupportedCommand,
    /// The destination could not be reached.
    #[error("{0}")]
    Connect(#[from] ConnectError),
}

/// A client stream with a read buffer for frame decoding.
///
/// Bytes read past the end of a frame (for example data a client pipelines
/// after its request) are kept and handed to the relay.
#[derive(Debug)]
pub struct Conn<S> {
    stream: S,
    buf: BytesMut,
}

impl<S: Stream> Conn<S> {
    /// Wrap a client stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: BytesMut::with_capacity(512),
        }
    }

    /// Read until `parse` succeeds or fails with a non-`Incomplete` error.
    ///
    /// # Errors
    /// Parse errors, I/O errors, or `UnexpectedEof` if the client closes.
    pub async fn read_frame<T>(&mut self, parse: Parser<T>) -> Result<T, SessionError> {
        loop {
            match parse(&self.buf) {
                Ok((value, used)) => {
                    self.buf.advance(used);
                    return Ok(value);
                }
                Err(ProtoError::Incomplete) => self.fill().await?,
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn fill(&mut self) -> io::Result<()> {
        self.buf.reserve(512);
        if self.stream.read_buf(&mut self.buf).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }

    /// Write and flush a message.
    ///
    /// # Errors
    /// I/O errors.
    pub async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    /// Send a failure reply and return `err`.
    pub(crate) async fn fail<E: Into<SessionError>>(&mut self, rep: Rep, err: E) -> SessionError {
        match self.send(&reply::encode_failure(rep)).await {
            Ok(()) => err.into(),
            Err(io) => io.into(),
        }
    }

    /// The stream and any buffered, unconsumed bytes.
    pub fn into_parts(self) -> (S, BytesMut) {
        (self.stream, self.buf)
    }
}

/// Serve one client connection to completion.
///
/// `peer` is the client's address and `local` the server address it
/// connected to (used for UDP ASSOCIATE).
///
/// # Errors
/// Why the session ended, if not cleanly.
pub async fn handle<S: Stream>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    ctx: &Ctx,
) -> Result<(), SessionError> {
    let mut conn = Conn::new(stream);
    let req = tokio::time::timeout(ctx.timeouts.handshake, handshake(&mut conn, ctx))
        .await
        .map_err(|_| SessionError::Timeout)??;
    match req.command {
        Command::Connect => relay::tcp::run(conn, &req.target, ctx).await,
        Command::UdpAssociate => relay::udp::run(conn, &req.target, peer, local, ctx).await,
        Command::Bind => Err(conn
            .fail(Rep::CommandNotSupported, SessionError::UnsupportedCommand)
            .await),
    }
}

async fn handshake<S: Stream>(conn: &mut Conn<S>, ctx: &Ctx) -> Result<Request, SessionError> {
    negotiate(conn, &ctx.auth).await?;
    match conn.read_frame(request::parse).await {
        Err(SessionError::Proto(e)) => Err(conn.fail(e.rep(), e).await),
        other => other,
    }
}

async fn negotiate<S: Stream>(
    conn: &mut Conn<S>,
    auth: &Authenticator,
) -> Result<(), SessionError> {
    let offered = conn.read_frame(greeting::parse).await?;
    let chosen = greeting::select_method(&offered.methods, auth.methods());
    conn.send(&greeting::encode_choice(chosen)).await?;
    match (chosen, auth) {
        (method::NO_ACCEPTABLE, _) => Err(SessionError::NoAcceptableMethod),
        (_, Authenticator::Password(store)) => authenticate(conn, Arc::clone(store)).await,
        (_, Authenticator::None) => Ok(()),
    }
}

async fn authenticate<S: Stream>(
    conn: &mut Conn<S>,
    store: Arc<CredentialStore>,
) -> Result<(), SessionError> {
    let creds = conn.read_frame(userpass::parse).await?;
    let user = String::from_utf8_lossy(&creds.username).into_owned();
    // Argon2 is deliberately slow; keep it off the async worker threads.
    let ok = tokio::task::spawn_blocking(move || store.verify(&creds.username, &creds.password))
        .await
        .unwrap_or(false);
    conn.send(&userpass::encode_status(ok)).await?;
    if ok {
        tracing::debug!(%user, "authenticated");
        Ok(())
    } else {
        tracing::warn!(%user, "authentication failed");
        Err(SessionError::AuthFailed)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::Limits;
    use crate::connector::{BoxFuture, TcpConnector, Upstream};
    use crate::resolver::tests::StaticResolver;
    use std::sync::LazyLock;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream, duplex};

    static STORE: LazyLock<Arc<CredentialStore>> = LazyLock::new(|| {
        let hash = crate::auth::hash_password(b"pw").unwrap();
        Arc::new(CredentialStore::parse(&format!("user:{hash}")).unwrap())
    });

    pub(crate) fn ctx(auth: Authenticator) -> Ctx {
        Ctx {
            auth,
            policy: EgressPolicy {
                allow_private: true,
                ..Default::default()
            },
            resolver: Arc::new(StaticResolver::default()),
            connector: Arc::new(TcpConnector),
            timeouts: Limits::default().timeouts(),
        }
    }

    pub(crate) fn password_ctx() -> Ctx {
        ctx(Authenticator::Password(Arc::clone(&STORE)))
    }

    const PEER: &str = "127.0.0.1:40000";
    const LOCAL: &str = "127.0.0.1:1080";

    /// Run a session against `client_bytes` and return what the server
    /// wrote back plus the session result.
    pub(crate) async fn exchange(
        ctx: Ctx,
        client_bytes: &[u8],
    ) -> (Vec<u8>, Result<(), SessionError>) {
        let (mut client, server) = duplex(4096);
        client.write_all(client_bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let result = handle(server, PEER.parse().unwrap(), LOCAL.parse().unwrap(), &ctx).await;
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        (out, result)
    }

    fn userpass(user: &[u8], pass: &[u8]) -> Vec<u8> {
        let mut v = vec![1, u8::try_from(user.len()).unwrap()];
        v.extend_from_slice(user);
        v.push(u8::try_from(pass.len()).unwrap());
        v.extend_from_slice(pass);
        v
    }

    #[test]
    fn methods_and_debug() {
        assert_eq!(Authenticator::None.methods(), &[method::NO_AUTH]);
        assert_eq!(password_ctx().auth.methods(), &[method::USER_PASS]);
        let dbg = format!("{:?}", ctx(Authenticator::None));
        assert!(dbg.contains("policy"));
    }

    #[tokio::test]
    async fn no_acceptable_method() {
        let (out, res) = exchange(password_ctx(), &[5, 1, 0]).await;
        assert_eq!(out, [5, 0xFF]);
        assert!(matches!(res, Err(SessionError::NoAcceptableMethod)));
    }

    #[tokio::test]
    async fn bad_password_rejected() {
        let mut bytes = vec![5, 1, 2];
        bytes.extend(userpass(b"user", b"wrong"));
        let (out, res) = exchange(password_ctx(), &bytes).await;
        assert_eq!(out, [5, 2, 1, 1]);
        assert!(matches!(res, Err(SessionError::AuthFailed)));
    }

    #[tokio::test]
    async fn good_password_then_bind_unsupported() {
        let mut bytes = vec![5, 2, 0, 2];
        bytes.extend(userpass(b"user", b"pw"));
        bytes.extend([5, 2, 0, 1, 1, 2, 3, 4, 0, 80]);
        let (out, res) = exchange(password_ctx(), &bytes).await;
        assert_eq!(&out[..4], [5, 2, 1, 0]);
        assert_eq!(&out[4..6], [5, Rep::CommandNotSupported as u8]);
        assert!(matches!(res, Err(SessionError::UnsupportedCommand)));
    }

    #[tokio::test]
    async fn malformed_request_gets_reply() {
        let (out, res) = exchange(ctx(Authenticator::None), &[5, 1, 0, 5, 9, 0, 1]).await;
        assert_eq!(&out[..2], [5, 0]);
        assert_eq!(out[3], Rep::CommandNotSupported as u8);
        assert!(matches!(
            res,
            Err(SessionError::Proto(ProtoError::UnsupportedCommand(9)))
        ));
        let (out, _) = exchange(ctx(Authenticator::None), &[5, 1, 0, 5, 1, 0, 9]).await;
        assert_eq!(out[3], Rep::AddressTypeNotSupported as u8);
    }

    #[tokio::test]
    async fn bad_greeting_version() {
        let (out, res) = exchange(ctx(Authenticator::None), &[4, 1, 0]).await;
        assert_eq!(out, [] as [u8; 0]);
        assert!(matches!(
            res,
            Err(SessionError::Proto(ProtoError::BadVersion(4)))
        ));
    }

    #[tokio::test]
    async fn eof_mid_handshake() {
        let (_, res) = exchange(ctx(Authenticator::None), &[5, 1]).await;
        assert!(
            matches!(res, Err(SessionError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_timeout() {
        let (_client, server) = duplex(64);
        let c = ctx(Authenticator::None);
        let res = handle(server, PEER.parse().unwrap(), LOCAL.parse().unwrap(), &c).await;
        assert!(matches!(res, Err(SessionError::Timeout)));
    }

    #[tokio::test]
    async fn fail_reports_write_errors() {
        let (client, server) = duplex(64);
        drop(client);
        let mut conn = Conn::new(server);
        let err = conn.fail(Rep::GeneralFailure, SessionError::Timeout).await;
        assert!(matches!(err, SessionError::Io(_)));
    }

    /// A connector that hands out one side of an in-memory pipe.
    pub(crate) struct PipeConnector(pub std::sync::Mutex<Option<DuplexStream>>);

    impl Connect for PipeConnector {
        fn connect(&self, _: SocketAddr) -> BoxFuture<'_, io::Result<Upstream>> {
            let stream = self.0.lock().unwrap().take();
            Box::pin(async move {
                let stream =
                    stream.ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))?;
                Ok(Upstream {
                    stream: Box::new(stream),
                    local_addr: "10.0.0.1:5555".parse().unwrap(),
                })
            })
        }
    }

    #[tokio::test]
    async fn connect_relays_pipelined_data() {
        let (up_server, mut up_far) = duplex(4096);
        let mut c = ctx(Authenticator::None);
        c.connector = Arc::new(PipeConnector(std::sync::Mutex::new(Some(up_server))));
        c.timeouts.idle = Duration::from_secs(5);
        let far = tokio::spawn(async move {
            let mut got = [0u8; 4];
            up_far.read_exact(&mut got).await.unwrap();
            up_far.write_all(b"pong").await.unwrap();
            got
        });
        let mut bytes = vec![5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 2, 0, 80];
        bytes.extend(b"ping");
        let (out, res) = exchange(c, &bytes).await;
        res.unwrap();
        assert_eq!(&far.await.unwrap(), b"ping");
        assert_eq!(&out[..2], [5, 0]);
        assert_eq!(&out[2..12], [5, 0, 0, 1, 10, 0, 0, 1, 0x15, 0xB3]);
        assert_eq!(&out[12..], b"pong");
    }

    #[tokio::test]
    async fn connect_failure_reply() {
        let mut c = ctx(Authenticator::None);
        c.connector = Arc::new(PipeConnector(std::sync::Mutex::new(None)));
        let (out, res) = exchange(c, &[5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 2, 0, 80]).await;
        assert_eq!(out[3], Rep::ConnectionRefused as u8);
        assert!(matches!(res, Err(SessionError::Connect(_))));
    }

    #[tokio::test]
    async fn connect_denied_by_policy() {
        let mut c = ctx(Authenticator::None);
        c.policy = EgressPolicy::default();
        let (out, res) = exchange(c, &[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await;
        assert_eq!(out[3], Rep::NotAllowed as u8);
        assert!(matches!(
            res,
            Err(SessionError::Connect(ConnectError::Denied(_)))
        ));
    }
}
