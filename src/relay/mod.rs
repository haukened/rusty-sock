//! Data relays for CONNECT (TCP) and UDP ASSOCIATE.

pub mod tcp;
pub mod udp;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::connector::Stream;

/// Copy data both ways until either side closes or no data flows in either
/// direction for `idle`.
///
/// # Errors
/// I/O errors from either stream.
pub async fn pump<A: Stream, B: Stream>(a: A, b: B, idle: Duration) -> io::Result<()> {
    let activity = Arc::new(AtomicU64::new(0));
    let mut a = Tracked {
        inner: a,
        activity: Arc::clone(&activity),
    };
    let mut b = Tracked {
        inner: b,
        activity: Arc::clone(&activity),
    };
    tokio::select! {
        res = tokio::io::copy_bidirectional(&mut a, &mut b) => res.map(drop),
        () = watchdog(&activity, idle) => {
            tracing::debug!("relay idle timeout");
            Ok(())
        }
    }
}

/// Resolve once a full `idle` period passes with no reads.
async fn watchdog(activity: &AtomicU64, idle: Duration) {
    let mut last = activity.load(Ordering::Relaxed);
    loop {
        tokio::time::sleep(idle).await;
        let now = activity.load(Ordering::Relaxed);
        if now == last {
            return;
        }
        last = now;
    }
}

/// A stream wrapper that counts successful reads.
struct Tracked<S> {
    inner: S,
    activity: Arc<AtomicU64>,
}

impl<S: Stream> AsyncRead for Tracked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.activity.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

impl<S: Stream> AsyncWrite for Tracked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn copies_both_ways() {
        let (a_near, mut a_far) = duplex(64);
        let (b_near, mut b_far) = duplex(64);
        let task = tokio::spawn(pump(a_near, b_near, Duration::from_secs(5)));
        a_far.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b_far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        b_far.write_all(b"world").await.unwrap();
        a_far.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        drop(a_far);
        drop(b_far);
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_closes() {
        let (a_near, mut a_far) = duplex(64);
        let (b_near, _b_far) = duplex(64);
        let idle = Duration::from_secs(10);
        let task = tokio::spawn(pump(a_near, b_near, idle));
        // Activity before the first deadline extends the relay once.
        tokio::time::sleep(idle / 2).await;
        a_far.write_all(b"x").await.unwrap();
        tokio::time::sleep(idle).await;
        assert!(!task.is_finished());
        tokio::time::sleep(idle * 2).await;
        assert!(task.is_finished());
        task.await.unwrap().unwrap();
    }
}
