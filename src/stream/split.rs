use std::{
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
use xiaoyong_value::unsync::async_mutex::Mutex;

use crate::stream::util::{
    flush_tls_writes,
    process_tls_reads,
    read_plaintext,
};

pub struct SharedTlsState<SW, C> {
    os_writer:  SW,
    connection: C,
    write_buf:  Option<BytesMut>,
}

impl<SW, C, SD> SharedTlsState<SW, C>
where
    SW: AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn flush(&mut self) -> io::Result<()> {
        flush_tls_writes(&mut self.connection, &mut self.os_writer, &mut self.write_buf).await
    }
}

pub struct TlsReadHalf<SR, SW, C> {
    os_reader: SR,
    shared:    Rc<Mutex<SharedTlsState<SW, C>>>,
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
            {
                // Lock to extract available plaintext
                let mut state = self.shared.lock().await;

                buf = match read_plaintext(&mut state.connection, buf) {
                    | Ok(res) => return res,
                    | Err(b) => b,
                };

                // Handshake/Side-effects might generate writes
                if state.connection.wants_write() {
                    if let Err(e) = state.flush().await {
                        return BufResult(Err(e), buf);
                    }
                }

                // If we're done handshaking/writing and rustls doesn't want to read anymore
                // (e.g. gracefully closed), return clean EOF without blocking on os_reader.
                if !state.connection.wants_read() {
                    return BufResult(Ok(0), buf);
                }
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

            // Re-lock to process the received ciphertext
            let mut state = self.shared.lock().await;
            if let Err(e) = process_tls_reads(&mut state.connection, b, &mut self.read_buf) {
                return BufResult(Err(e), buf);
            }
        }
    }
}

pub struct TlsWriteHalf<SW, C> {
    shared: Rc<Mutex<SharedTlsState<SW, C>>>,
}

impl<SW, C, SD> AsyncWrite for TlsWriteHalf<SW, C>
where
    SW: AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let mut state = self.shared.lock().await;

        let slice = buf.as_init();
        let written = match state.connection.writer().write(slice) {
            | Ok(n) => n,
            | Err(e) => return BufResult(Err(e), buf),
        };

        if let Err(e) = state.flush().await {
            return BufResult(Err(e), buf);
        }

        BufResult(Ok(written), buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        let mut state = self.shared.lock().await;
        state.connection.writer().flush()?;
        state.flush().await?;
        state.os_writer.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let mut state = self.shared.lock().await;
        state.connection.send_close_notify();
        state.flush().await?;
        state.os_writer.shutdown().await
    }
}

/// Constructs independent Read and Write halves from split OS streams and a TLS
/// connection.
pub fn split_tls_stream<SR, SW, C>(
    os_reader: SR,
    os_writer: SW,
    connection: C,
) -> (TlsReadHalf<SR, SW, C>, TlsWriteHalf<SW, C>) {
    let shared_state = Rc::new(Mutex::new(SharedTlsState {
        os_writer,
        connection,
        write_buf: Some(BytesMut::with_capacity(4096)),
    }));

    let read_half = TlsReadHalf {
        os_reader,
        shared: Rc::clone(&shared_state),
        read_buf: Some(BytesMut::with_capacity(4096)),
    };

    let write_half = TlsWriteHalf {
        shared: shared_state
    };

    (read_half, write_half)
}

/// Constructs independent Read and Write halves from split OS streams and a TLS
/// connection.
pub fn split_tls_stream_with_capacity<SR, SW, C>(
    os_reader: SR,
    os_writer: SW,
    connection: C,
    capacity: usize,
) -> (TlsReadHalf<SR, SW, C>, TlsWriteHalf<SW, C>) {
    let shared_state = Rc::new(Mutex::new(SharedTlsState {
        os_writer,
        connection,
        write_buf: Some(BytesMut::with_capacity(capacity)),
    }));

    let read_half = TlsReadHalf {
        os_reader,
        shared: Rc::clone(&shared_state),
        read_buf: Some(BytesMut::with_capacity(capacity)),
    };

    let write_half = TlsWriteHalf {
        shared: shared_state
    };

    (read_half, write_half)
}
