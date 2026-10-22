//! CONNECT: resolve, connect, reply, then relay.

use tokio::io::AsyncWriteExt;

use crate::connector::{Stream, Upstream, connect_any};
use crate::error::ConnectError;
use crate::proto::{Rep, TargetAddr, reply};
use crate::resolver::resolve_target;
use crate::session::{Conn, Ctx, SessionError};

/// Handle a CONNECT request.
///
/// # Errors
/// Connection or relay failures. A failure reply is sent before returning.
pub async fn run<S: Stream>(
    mut conn: Conn<S>,
    target: &TargetAddr,
    ctx: &Ctx,
) -> Result<(), SessionError> {
    let upstream = match open(target, ctx).await {
        Ok(up) => up,
        Err(e) => return Err(conn.fail(e.rep(), e).await),
    };
    conn.send(&reply::encode(Rep::Succeeded, upstream.local_addr))
        .await?;
    let (client, pending) = conn.into_parts();
    let mut remote = upstream.stream;
    remote.write_all(&pending).await?;
    super::pump(client, remote, ctx.timeouts.idle).await?;
    Ok(())
}

async fn open(target: &TargetAddr, ctx: &Ctx) -> Result<Upstream, ConnectError> {
    let addrs = resolve_target(&*ctx.resolver, &ctx.policy, target, ctx.timeouts.dns).await?;
    tracing::debug!(?target, ?addrs, "connecting");
    connect_any(&*ctx.connector, &addrs, ctx.timeouts.connect).await
}
