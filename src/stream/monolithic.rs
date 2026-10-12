use bytes_rc::BytesMut;
use compio_buf::{
    BufResult,
    IntoInner as _,
    IoBuf,
    IoBufMut,
};
use compio_io::{
    AsyncRead,
    AsyncWrite,
    util::Splittable,
};
use rustls::{
    ConnectionCommon,
    SideData,
};

use crate::{
    DEFAULT_BUF_CAPACITY,
    stream::{
        split::{
            TlsReadHalf,
            TlsWriteHalf,
            split_tls_stream_with_buffers,
        },
        util::{
            flush_tls_writes,
            process_tls_reads,
            read_plaintext,
        },
    },
    util::io_buffer::IoBuffer,
};

pub struct TlsStream<S, C> {
    io:         S,
    connection: C,
    read_buf:   Option<BytesMut>,
    write_buf:  Option<BytesMut>,
}

/// Read and write halves produced by splitting a [`TlsStream`].
pub type TlsStreamHalves<S, C> = (
    TlsReadHalf<<S as Splittable>::ReadHalf, <S as Splittable>::WriteHalf, C>,
    TlsWriteHalf<<S as Splittable>::WriteHalf, C>,
);

#[cfg(unix)]
use std::os::unix::io::{
    AsFd,
    AsRawFd,
    BorrowedFd,
    RawFd,
};
use std::{
    io::{
        self,
        Write as _,
    },
    ops::DerefMut,
};

#[cfg(unix)]
impl<S: AsRawFd, C> AsRawFd for TlsStream<S, C> {
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

#[cfg(unix)]
impl<S: AsFd, C> AsFd for TlsStream<S, C> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.io.as_fd()
    }
}

#[cfg(windows)]
use std::os::windows::io::{
    AsRawSocket,
    AsSocket,
    BorrowedSocket,
    RawSocket,
};

#[cfg(windows)]
impl<S: AsRawSocket, C> AsRawSocket for TlsStream<S, C> {
    fn as_raw_socket(&self) -> RawSocket {
        self.io.as_raw_socket()
    }
}

#[cfg(windows)]
impl<S: AsSocket, C> AsSocket for TlsStream<S, C> {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.io.as_socket()
    }
}

impl<S, C, SD> TlsStream<S, C>
where
    S: AsyncRead + AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    pub(crate) fn new(io: S, connection: C) -> Self {
        Self::with_capacity(io, connection, DEFAULT_BUF_CAPACITY)
    }

    pub(crate) fn with_capacity(io: S, connection: C, capacity: usize) -> Self {
        Self {
            io,
            connection,
            read_buf: Some(BytesMut::with_capacity(capacity)),
            write_buf: Some(BytesMut::with_capacity(capacity)),
        }
    }

    pub fn get_ref(&self) -> (&S, &C) {
        (&self.io, &self.connection)
    }

    pub fn get_mut(&mut self) -> (&mut S, &mut C) {
        (&mut self.io, &mut self.connection)
    }

    /// Extracts the transport and Rustls connection, discarding local TLS
    /// buffers. Use [`Self::into_split`] to split a stream without losing
    /// buffered data.
    pub fn into_inner(self) -> (S, C) {
        (self.io, self.connection)
    }

    async fn flush_tls_writes(&mut self) -> io::Result<()> {
        flush_tls_writes(&mut self.connection, &mut self.io, &mut self.write_buf).await
    }

    async fn fetch_tls_reads(&mut self) -> io::Result<usize> {
        let mut rbuf = self.read_buf.take().unwrap_or_else(|| BytesMut::with_capacity(4096));
        // Rustls may consume only a prefix of a transport read. Feed the
        // retained ciphertext before waiting for the peer to send more.
        if !rbuf.is_empty() {
            process_tls_reads(&mut self.connection, rbuf, &mut self.read_buf)?;
            return Ok(0);
        }
        if rbuf.len() == rbuf.capacity() {
            rbuf.reserve(4096);
        }

        let init_len = rbuf.len();
        let BufResult(res, slice) = self.io.read(IoBuffer(rbuf).slice(init_len ..)).await;
        let mut b = slice.into_inner().into_inner();

        let n = match res {
            | Ok(0) => {
                self.read_buf = Some(b);
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            },
            | Ok(n) => {
                unsafe { b.set_len(init_len + n) };
                n
            },
            | Err(e) => {
                self.read_buf = Some(b);
                return Err(e);
            },
        };

        process_tls_reads(&mut self.connection, b, &mut self.read_buf)?;
        Ok(n)
    }

    pub(crate) async fn handshake(&mut self) -> io::Result<()> {
        while self.connection.is_handshaking() {
            while self.connection.wants_write() {
                self.flush_tls_writes().await?;
            }
            if self.connection.wants_read() {
                self.fetch_tls_reads().await?;
            } else if !self.connection.wants_write() {
                break;
            }
        }
        // Processing the peer's final flight can complete our handshake while
        // queuing a final flight that the peer still needs to complete theirs.
        self.flush_tls_writes().await
    }
}

impl<S: Splittable, C> TlsStream<S, C> {
    /// Splits the transport and TLS state without discarding buffered data.
    pub fn into_split(self) -> TlsStreamHalves<S, C> {
        let (reader, writer) = self.io.split();
        split_tls_stream_with_buffers(reader, writer, self.connection, self.read_buf, self.write_buf)
    }
}

impl<S, C, SD> AsyncRead for TlsStream<S, C>
where
    S: AsyncRead + AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            // Attempt to read plaintext
            buf = match read_plaintext(&mut self.connection, buf) {
                | Ok(res) => return res,
                | Err(b) => b,
            };

            // Drive TLS state machine
            if self.connection.wants_write()
                && let Err(e) = self.flush_tls_writes().await
            {
                return BufResult(Err(e), buf);
            }

            if self.connection.wants_read() {
                if let Err(e) = self.fetch_tls_reads().await {
                    return BufResult(Err(e), buf);
                }
            } else if !self.connection.wants_write() {
                return BufResult(Ok(0), buf);
            }
        }
    }
}

impl<S, C, SD> AsyncWrite for TlsStream<S, C>
where
    S: AsyncRead + AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let slice = buf.as_init();
        let written = match self.connection.writer().write(slice) {
            | Ok(n) => n,
            | Err(e) => return BufResult(Err(e), buf),
        };

        if let Err(e) = self.flush_tls_writes().await {
            return BufResult(Err(e), buf);
        }

        BufResult(Ok(written), buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.connection.writer().flush()?;
        self.flush_tls_writes().await?;
        self.io.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.connection.send_close_notify();
        self.flush_tls_writes().await?;
        self.io.shutdown().await
    }
}
