use std::{
    io::{
        self,
        Cursor,
        Read as _,
        Write,
    },
    ops::DerefMut,
};

use compio_buf::{
    BufResult,
    IoBuf,
    IoBufMut,
    bytes::BytesMut,
};
use compio_io::{
    AsyncRead,
    AsyncWrite,
};
use rustls::{
    ConnectionCommon,
    SideData,
};

struct BytesMutWriter<'a>(&'a mut BytesMut);

impl Write for BytesMutWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
pub struct TlsStream<S, C> {
    io:         S,
    connection: C,

    // Intermediate buffers for ciphertext.
    read_buf:  Option<BytesMut>,
    write_buf: Option<BytesMut>,
}

#[cfg(unix)]
use std::os::unix::io::{
    AsFd,
    AsRawFd,
    BorrowedFd,
    RawFd,
};

#[cfg(unix)]
impl<S, C> AsRawFd for TlsStream<S, C>
where
    S: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.io.as_raw_fd()
    }
}

#[cfg(unix)]
impl<S, C> AsFd for TlsStream<S, C>
where
    S: AsFd,
{
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
impl<S, C> AsRawSocket for TlsStream<S, C>
where
    S: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.io.as_raw_socket()
    }
}

#[cfg(windows)]
impl<S, C> AsSocket for TlsStream<S, C>
where
    S: AsSocket,
{
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
        Self {
            io,
            connection,
            read_buf: Some(BytesMut::with_capacity(4096)),
            write_buf: Some(BytesMut::with_capacity(4096)),
        }
    }

    pub fn get_ref(&self) -> (&S, &C) {
        (&self.io, &self.connection)
    }

    pub fn get_mut(&mut self) -> (&mut S, &mut C) {
        (&mut self.io, &mut self.connection)
    }

    pub fn into_inner(self) -> (S, C) {
        (self.io, self.connection)
    }

    /// Pull generated ciphertext from `rustls` and pushes it to the underlying
    /// OS socket.
    async fn flush_tls_writes(&mut self) -> io::Result<()> {
        let mut wbuf = self.write_buf.take().unwrap_or_else(|| BytesMut::with_capacity(4096));

        // Drain all pending TLS ciphertext into our intermediate buffer
        while self.connection.wants_write() {
            if let Err(e) = self.connection.write_tls(&mut BytesMutWriter(&mut wbuf)) {
                self.write_buf = Some(wbuf);
                return Err(e);
            }
        }

        // Flush the buffer to the OS, handling potential partial writes
        while wbuf.buf_len() > 0 {
            let BufResult(res, mut b) = self.io.write(wbuf).await;

            let n = match res {
                | Ok(n) => n,
                | Err(e) => {
                    self.write_buf = Some(b);
                    return Err(e);
                },
            };

            if n == 0 {
                self.write_buf = Some(b);
                return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write tls data"));
            }

            let len = b.buf_len();
            if n == len {
                // Fully written
                b.clear();
                wbuf = b;
                break;
            } else {
                // Partial write: shift remaining unwritten bytes to the front
                b.copy_within(n .. len, 0);
                unsafe { b.set_len(len - n) };
                wbuf = b;
            }
        }

        self.write_buf = Some(wbuf);
        Ok(())
    }

    /// Pull ciphertext from the OS socket and feeds it into the `rustls`.
    async fn fetch_tls_reads(&mut self) -> io::Result<usize> {
        let mut rbuf = self.read_buf.take().unwrap_or_else(|| BytesMut::with_capacity(4096));

        // Ensure we have uninitialized capacity available for the OS to write into
        if rbuf.buf_len() == rbuf.buf_capacity() {
            rbuf.reserve(4096);
        }

        let BufResult(res, mut b) = self.io.read(rbuf).await;

        let n = match res {
            | Ok(0) => {
                self.read_buf = Some(b);
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            },
            | Ok(n) => n,
            | Err(e) => {
                self.read_buf = Some(b);
                return Err(e);
            },
        };

        // Pass the initialized bytes to rustls
        let mut cursor = Cursor::new(b.as_init());
        let read_res = self.connection.read_tls(&mut cursor);

        // Check how many bytes rustls actually consumed
        let consumed = cursor.position() as usize;
        let len = b.buf_len();

        if consumed == len {
            b.clear();
        } else {
            // Shift leftover, unconsumed ciphertext to the front for the next read cycle
            b.copy_within(consumed .. len, 0);
            unsafe { b.set_len(len - consumed) };
        }

        self.read_buf = Some(b);

        read_res?;

        self.connection
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

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
                // Handshake is stalled or finished
                break;
            }
        }
        Ok(())
    }
}

impl<S, C, SD> AsyncRead for TlsStream<S, C>
where
    S: AsyncRead + AsyncWrite,
    C: std::ops::DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            let init_len = buf.buf_len();
            let cap = buf.buf_capacity();

            // Prevent undefined behavior or infinite loops if passed a completely full
            // buffer.
            if init_len == cap {
                return BufResult(Ok(0), buf);
            }

            // Try to yield existing plaintext
            let mut reader = self.connection.reader();

            // Extract the uninitialized portion of the buffer to write plaintext into.
            let slice =
                unsafe { std::slice::from_raw_parts_mut(buf.buf_mut_ptr().cast::<u8>().add(init_len), cap - init_len) };

            match reader.read(slice) {
                | Ok(n) if n > 0 => unsafe {
                    // Update the initialized length marker in the compio buffer
                    buf.advance_to(init_len + n);
                    return BufResult(Ok(n), buf);
                },
                | Err(e) if e.kind() != io::ErrorKind::WouldBlock => return BufResult(Err(e), buf),
                | _ => {}, // Need more data from the socket
            }

            // Drive the TLS state machine
            if self.connection.wants_write() {
                if let Err(e) = self.flush_tls_writes().await {
                    return BufResult(Err(e), buf);
                }
            }

            if self.connection.wants_read() {
                if let Err(e) = self.fetch_tls_reads().await {
                    return BufResult(Err(e), buf);
                }
            } else if !self.connection.wants_write() {
                // Connection closed cleanly or EOF
                return BufResult(Ok(0), buf);
            }
        }
    }
}

impl<S, C, SD> AsyncWrite for TlsStream<S, C>
where
    S: AsyncRead + AsyncWrite,
    C: std::ops::DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        // Extract the initialized slice representing the plaintext to be sent
        let slice = buf.as_init();

        let written = match self.connection.writer().write(slice) {
            | Ok(n) => n,
            | Err(e) => return BufResult(Err(e), buf),
        };

        // Push the newly generated ciphertext down to the OS
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
