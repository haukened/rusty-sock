//! Accept loop with a connection cap and optional TLS.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::session::{Ctx, SessionError, handle};

/// A bound SOCKS5 server.
pub struct Server {
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    ctx: Arc<Ctx>,
    permits: Arc<Semaphore>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("listener", &self.listener)
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Bind to `addr`.
    ///
    /// # Errors
    /// If the address cannot be bound.
    pub async fn bind(
        addr: SocketAddr,
        ctx: Ctx,
        tls: Option<TlsAcceptor>,
        max_connections: usize,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            tls,
            ctx: Arc::new(ctx),
            permits: Arc::new(Semaphore::new(max_connections)),
        })
    }

    /// The bound address.
    ///
    /// # Errors
    /// If the socket address cannot be queried.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept connections until `shutdown` resolves.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                accepted = self.listener.accept() => self.dispatch(accepted).await,
            }
        }
    }

    async fn dispatch(&self, accepted: io::Result<(TcpStream, SocketAddr)>) {
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                // Typically fd exhaustion; back off instead of spinning.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                return;
            }
        };
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            tracing::warn!(%peer, "connection limit reached; dropping");
            return;
        };
        let ctx = Arc::clone(&self.ctx);
        let tls = self.tls.clone();
        tokio::spawn(async move {
            let result = serve(stream, peer, tls, &ctx).await;
            drop(permit);
            match result {
                Ok(()) => tracing::debug!(%peer, "session closed"),
                Err(e) => tracing::info!(%peer, error = %e, "session ended"),
            }
        });
    }
}

async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    tls: Option<TlsAcceptor>,
    ctx: &Ctx,
) -> Result<(), SessionError> {
    let local = stream.local_addr()?;
    stream.set_nodelay(true)?;
    let Some(tls) = tls else {
        return handle(stream, peer, local, ctx).await;
    };
    let stream = tokio::time::timeout(ctx.timeouts.handshake, tls.accept(stream))
        .await
        .map_err(|_| SessionError::Timeout)??;
    handle(stream, peer, local, ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Authenticator, tests::ctx};

    async fn server() -> Server {
        Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            ctx(Authenticator::None),
            None,
            1,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn debug_hides_internals() {
        let dbg = format!("{:?}", server().await);
        assert!(dbg.contains("tls: false"));
    }

    #[tokio::test(start_paused = true)]
    async fn accept_errors_back_off() {
        let s = server().await;
        let start = tokio::time::Instant::now();
        s.dispatch(Err(io::Error::other("EMFILE"))).await;
        assert!(start.elapsed() >= Duration::from_millis(100));
    }
}
