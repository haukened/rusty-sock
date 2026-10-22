//! Outbound TCP connections.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::ConnectError;

/// A boxed, sendable future.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A bidirectional byte stream.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// An established outbound connection.
pub struct Upstream {
    /// The connected stream.
    pub stream: Box<dyn Stream>,
    /// The local address used, reported to the client as `BND.ADDR`.
    pub local_addr: SocketAddr,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upstream")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

/// Opens outbound connections. Abstracted so sessions can be tested
/// without touching the network.
pub trait Connect: Send + Sync {
    /// Connect to `addr`.
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Upstream>>;
}

/// Connects with real TCP sockets.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpConnector;

impl Connect for TcpConnector {
    fn connect(&self, addr: SocketAddr) -> BoxFuture<'_, io::Result<Upstream>> {
        Box::pin(async move {
            let stream = TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            let local_addr = stream.local_addr()?;
            Ok(Upstream {
                stream: Box::new(stream),
                local_addr,
            })
        })
    }
}

/// Try each address in order until one connects, within an overall deadline.
///
/// # Errors
/// [`ConnectError::Timeout`] if the deadline passes, otherwise the last
/// connection error ([`ConnectError::NoAddresses`] if `addrs` is empty).
pub async fn connect_any(
    connector: &dyn Connect,
    addrs: &[SocketAddr],
    deadline: Duration,
) -> Result<Upstream, ConnectError> {
    let attempt = async {
        let mut last = ConnectError::NoAddresses;
        for &addr in addrs {
            match connector.connect(addr).await {
                Ok(up) => return Ok(up),
                Err(e) => last = ConnectError::Io(e),
            }
        }
        Err(last)
    };
    tokio::time::timeout(deadline, attempt)
        .await
        .unwrap_or(Err(ConnectError::Timeout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const SECOND: Duration = Duration::from_secs(1);

    #[tokio::test]
    async fn connects_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = connect_any(&TcpConnector, &[addr], SECOND).await.unwrap();
        assert_eq!(up.local_addr.ip(), addr.ip());
        assert!(format!("{up:?}").contains("local_addr"));
    }

    #[tokio::test]
    async fn falls_through_to_next_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = listener.local_addr().unwrap();
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        assert!(
            connect_any(&TcpConnector, &[closed, good], SECOND)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn reports_last_error() {
        let closed = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let err = connect_any(&TcpConnector, &[closed], SECOND)
            .await
            .unwrap_err();
        assert_eq!(err.rep(), crate::proto::Rep::ConnectionRefused);
        let err = connect_any(&TcpConnector, &[], SECOND).await.unwrap_err();
        assert!(matches!(err, ConnectError::NoAddresses));
    }

    struct Hang;
    impl Connect for Hang {
        fn connect(&self, _: SocketAddr) -> BoxFuture<'_, io::Result<Upstream>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn times_out() {
        let err = connect_any(&Hang, &["1.1.1.1:80".parse().unwrap()], SECOND)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectError::Timeout));
    }
}
