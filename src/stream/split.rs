use std::{
    cell::RefCell,
    io::{
        self,
        Write as _,
    },
    ops::DerefMut,
    rc::Rc,
};

use compio_buf::{
    BufResult,
    IntoInner as _,
    IoBuf,
    IoBufMut,
    bytes::{
        Bytes,
        BytesMut,
    },
};
use compio_io::{
    AsyncRead,
    AsyncWrite,
};
use rustls::{
    ConnectionCommon,
    SideData,
};
use xiaoyong_value::unsync::async_mutex::Mutex;

use crate::{
    stream::util::{
        process_tls_reads,
        read_plaintext,
    },
    util::bytes_bridge::BytesMutWriter,
};

pub struct SharedTlsState<SW, C> {
    connection: RefCell<C>,
    writer:     Mutex<TlsWriter<SW>>,
}

struct TlsWriter<SW> {
    os_writer:       SW,
    write_buf:       BytesMut,
    pending:         Bytes,
    written:         usize,
    write_in_flight: bool,
}

impl<SW: AsyncWrite> TlsWriter<SW> {
    fn check_available(&self) -> io::Result<()> {
        if self.write_in_flight {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS transport write has an unknown result; further output is disabled",
            ));
        }
        Ok(())
    }

    async fn flush_tls<C, SD>(&mut self, connection: &RefCell<C>) -> io::Result<()>
    where
        C: DerefMut<Target = ConnectionCommon<SD>>,
        SD: SideData,
    {
        self.check_available()?;
        loop {
            if self.pending.is_empty() {
                {
                    let mut connection = connection.borrow_mut();
                    while connection.wants_write() {
                        connection.write_tls(&mut BytesMutWriter(&mut self.write_buf))?;
                    }
                }
                if self.write_buf.is_empty() {
                    return Ok(());
                }
                self.pending = std::mem::take(&mut self.write_buf).freeze();
            }

            // Keep the full batch in shared writer state. Only a cheap immutable
            // slice is owned by the OS operation, so errors cannot lose the tail.
            let remaining = self.pending.len() - self.written;
            // Cancellation leaves this set. The next writer must not replay a
            // batch whose OS write might already have sent an unknown prefix.
            self.write_in_flight = true;
            let ciphertext = Bytes::slice(&self.pending, self.written ..);
            let BufResult(result, returned) = self.os_writer.write(ciphertext).await;
            self.write_in_flight = false;
            drop(returned);
            let count = match result {
                | Ok(count) => count,
                | Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                | Err(e) => return Err(e),
            };
            if count == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write tls data"));
            }
            if count > remaining {
                self.write_in_flight = true;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid TLS transport write count"));
            }
            self.written += count;
            if self.written == self.pending.len() {
                let batch = std::mem::take(&mut self.pending);
                self.write_buf = batch.try_into_mut().unwrap_or_else(|_| BytesMut::with_capacity(4096));
                self.write_buf.clear();
                self.written = 0;
            }
        }
    }
}

impl<SW, C, SD> SharedTlsState<SW, C>
where
    SW: AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn flush(&self) -> io::Result<()> {
        self.writer.lock().await.flush_tls(&self.connection).await
    }
}

pub struct TlsReadHalf<SR, SW, C> {
    os_reader: SR,
    shared:    Rc<SharedTlsState<SW, C>>,
    read_buf:  Option<BytesMut>,
}

impl<SR, SW, C, SD> AsyncRead for TlsReadHalf<SR, SW, C>
where
    SR: AsyncRead,
    SW: AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        loop {
            let (wants_read, wants_write) = {
                // Rustls access is synchronous; no borrow crosses an OS await.
                let mut connection = self.shared.connection.borrow_mut();

                buf = match read_plaintext(&mut *connection, buf) {
                    | Ok(res) => return res,
                    | Err(b) => b,
                };

                // Rustls may consume only a prefix of a transport read. Feed
                // retained ciphertext before awaiting OS input.
                if connection.wants_read()
                    && let Some(b) = self.read_buf.take()
                {
                    if !b.is_empty() {
                        if let Err(e) = process_tls_reads(&mut *connection, b, &mut self.read_buf) {
                            return BufResult(Err(e), buf);
                        }
                        continue;
                    }
                    self.read_buf = Some(b);
                }
                (connection.wants_read(), connection.wants_write())
            };

            if wants_write {
                // An active writer drains newly generated TLS output after its
                // pending batch. Do not make readable input wait for its lock.
                if let Some(mut writer) = self.shared.writer.try_lock() {
                    if let Err(e) = writer.flush_tls(&self.shared.connection).await {
                        return BufResult(Err(e), buf);
                    }
                    continue;
                } else if !wants_read {
                    // During a handshake Rustls can require output before it
                    // accepts more input. Wait only in that case.
                    if let Err(e) = self.shared.flush().await {
                        return BufResult(Err(e), buf);
                    }
                    continue;
                }
            }
            if !wants_read {
                return BufResult(Ok(0), buf);
            }

            // Wait on OS Reader for ciphertext
            let mut rbuf = self.read_buf.take().unwrap_or_else(|| BytesMut::with_capacity(4096));
            if rbuf.buf_len() == rbuf.buf_capacity() {
                rbuf.reserve(4096);
            }

            let init_len = rbuf.buf_len();
            let BufResult(res, slice) = self.os_reader.read(rbuf.slice(init_len ..)).await;
            let mut b = slice.into_inner();

            match res {
                | Ok(0) => {
                    self.read_buf = Some(b);
                    return BufResult(Err(io::Error::from(io::ErrorKind::UnexpectedEof)), buf);
                },
                | Ok(n) => {
                    unsafe { b.set_len(init_len + n) };
                },
                | Err(e) => {
                    self.read_buf = Some(b);
                    return BufResult(Err(e), buf);
                },
            };

            let mut connection = self.shared.connection.borrow_mut();
            if let Err(e) = process_tls_reads(&mut *connection, b, &mut self.read_buf) {
                return BufResult(Err(e), buf);
            }
        }
    }
}

/// The write half of a split TLS stream.
///
/// Dropping a future during a pending transport write leaves the number of
/// bytes sent unknown. Further writes, flushes, and shutdowns then return
/// [`io::ErrorKind::BrokenPipe`] to prevent ciphertext loss or replay. Reads
/// remain available. Dropping a future that only waits for the writer lock does
/// not invalidate the write half.
pub struct TlsWriteHalf<SW, C> {
    shared: Rc<SharedTlsState<SW, C>>,
}

impl<SW, C, SD> AsyncWrite for TlsWriteHalf<SW, C>
where
    SW: AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let mut writer = self.shared.writer.lock().await;
        if let Err(e) = writer.check_available() {
            return BufResult(Err(e), buf);
        }

        let slice = buf.as_init();
        let written = match self.shared.connection.borrow_mut().writer().write(slice) {
            | Ok(n) => n,
            | Err(e) => return BufResult(Err(e), buf),
        };

        if let Err(e) = writer.flush_tls(&self.shared.connection).await {
            return BufResult(Err(e), buf);
        }

        BufResult(Ok(written), buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        let mut writer = self.shared.writer.lock().await;
        writer.check_available()?;
        self.shared.connection.borrow_mut().writer().flush()?;
        loop {
            writer.flush_tls(&self.shared.connection).await?;
            writer.os_writer.flush().await?;
            // The reader can generate more TLS output while the OS flush is
            // pending. Include that output before reporting a completed flush.
            if !self.shared.connection.borrow().wants_write() {
                return Ok(());
            }
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let mut writer = self.shared.writer.lock().await;
        writer.check_available()?;
        self.shared.connection.borrow_mut().send_close_notify();
        writer.flush_tls(&self.shared.connection).await?;
        writer.os_writer.shutdown().await
    }
}

/// Constructs independent Read and Write halves from split OS streams and a TLS
/// connection.
pub fn split_tls_stream<SR, SW, C>(
    os_reader: SR,
    os_writer: SW,
    connection: C,
) -> (TlsReadHalf<SR, SW, C>, TlsWriteHalf<SW, C>) {
    split_tls_stream_with_capacity(os_reader, os_writer, connection, 4096)
}

/// Constructs independent Read and Write halves from split OS streams and a TLS
/// connection.
pub fn split_tls_stream_with_capacity<SR, SW, C>(
    os_reader: SR,
    os_writer: SW,
    connection: C,
    capacity: usize,
) -> (TlsReadHalf<SR, SW, C>, TlsWriteHalf<SW, C>) {
    split_tls_stream_with_buffers(
        os_reader,
        os_writer,
        connection,
        Some(BytesMut::with_capacity(capacity)),
        Some(BytesMut::with_capacity(capacity)),
    )
}

pub(crate) fn split_tls_stream_with_buffers<SR, SW, C>(
    os_reader: SR,
    os_writer: SW,
    connection: C,
    read_buf: Option<BytesMut>,
    write_buf: Option<BytesMut>,
) -> (TlsReadHalf<SR, SW, C>, TlsWriteHalf<SW, C>) {
    let shared_state = Rc::new(SharedTlsState {
        connection: RefCell::new(connection),
        writer: Mutex::new(TlsWriter {
            os_writer,
            write_buf: write_buf.unwrap_or_else(|| BytesMut::with_capacity(4096)),
            pending: Bytes::new(),
            written: 0,
            write_in_flight: false,
        }),
    });

    let read_half = TlsReadHalf {
        os_reader,
        shared: Rc::clone(&shared_state),
        read_buf,
    };

    let write_half = TlsWriteHalf {
        shared: shared_state
    };

    (read_half, write_half)
}
