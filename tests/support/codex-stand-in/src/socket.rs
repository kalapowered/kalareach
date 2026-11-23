//! The stream the terminal reaches a gateway's socket by.
//!
//! On Unix it is the runtime's own Unix-domain stream. Windows has no such type in the runtime, so
//! the socket is a non-blocking `uds_windows` stream registered with `async-io`, read and written
//! through the tokio traits, as the host's own socket on that platform is.

/// The terminal's connection to the gateway.
#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;

/// Connects to the socket at `path`.
///
/// # Errors
///
/// Returns the system's failure.
#[cfg(unix)]
pub async fn connect(path: &str) -> std::io::Result<Stream> {
    tokio::net::UnixStream::connect(path).await
}

#[cfg(windows)]
pub use windows::connect;

#[cfg(windows)]
mod windows {
    #![expect(
        unsafe_code,
        reason = "the reactor trusts that a socket's reads and writes leave it registered, which only the implementer can say"
    )]

    use std::io::{Read, Write};
    use std::os::windows::io::{AsSocket, BorrowedSocket};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_io::{Async, IoSafe};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt as _};

    /// A socket lent to the reactor, which reads and writes it and nothing else.
    #[derive(Debug)]
    struct Registered(uds_windows::UnixStream);

    impl AsSocket for Registered {
        fn as_socket(&self) -> BorrowedSocket<'_> {
            self.0.as_socket()
        }
    }

    impl Read for Registered {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl Write for Registered {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    // SAFETY: reading and writing only call the socket's own read and write, which neither close the
    // socket nor hand it to anything else, so the reactor's registration stays true.
    unsafe impl IoSafe for Registered {}

    /// The terminal's connection to the gateway.
    #[derive(Debug)]
    pub struct Stream {
        inner: Compat<Async<Registered>>,
    }

    /// Connects to the socket at `path`.
    ///
    /// # Errors
    ///
    /// Returns the system's failure.
    pub async fn connect(path: &str) -> std::io::Result<Stream> {
        let path = path.to_owned();
        let socket = tokio::task::spawn_blocking(move || uds_windows::UnixStream::connect(path))
            .await
            .map_err(std::io::Error::other)??;
        Ok(Stream {
            inner: Async::new(Registered(socket))?.compat(),
        })
    }

    impl AsyncRead for Stream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for Stream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }
}
