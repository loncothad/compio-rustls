use std::{
    io::{
        self,
        Read as _,
    },
    ops::DerefMut,
};

use compio_buf::{
    BufResult,
    IoBuf as _,
    IoBufMut,
    bytes::BytesMut,
};
use compio_io::AsyncWrite;
use rustls::{
    ConnectionCommon,
    SideData,
};

use crate::util::bytes_bridge::BytesMutWriter;

/// Pull generated ciphertext from `rustls` and push it to the underlying OS
/// socket.
pub(crate) async fn flush_tls_writes<W, C, SD>(
    connection: &mut C,
    io: &mut W,
    write_buf: &mut Option<BytesMut>,
) -> io::Result<()>
where
    W: AsyncWrite,
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let mut wbuf = write_buf.take().unwrap_or_else(|| BytesMut::with_capacity(4096));

    // Drain all pending TLS ciphertext into our intermediate buffer
    while connection.wants_write() {
        if let Err(e) = connection.write_tls(&mut BytesMutWriter(&mut wbuf)) {
            *write_buf = Some(wbuf);
            return Err(e);
        }
    }

    // Flush the buffer to the OS
    while wbuf.buf_len() > 0 {
        let BufResult(res, mut b) = io.write(wbuf).await;

        let n = match res {
            | Ok(n) => n,
            | Err(e) => {
                *write_buf = Some(b);
                return Err(e);
            },
        };

        if n == 0 {
            *write_buf = Some(b);
            return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write tls data"));
        }

        let len = b.buf_len();
        if n == len {
            b.clear();
            wbuf = b;
            break;
        } else {
            b.copy_within(n .. len, 0);
            unsafe { b.set_len(len - n) };
            wbuf = b;
        }
    }

    *write_buf = Some(wbuf);
    Ok(())
}

/// Feeds newly received OS ciphertext into rustls, processing the state
/// machine.
pub(crate) fn process_tls_reads<C, SD>(
    connection: &mut C,
    mut b: BytesMut,
    read_buf: &mut Option<BytesMut>,
) -> io::Result<()>
where
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let mut cursor = io::Cursor::new(b.as_init());
    let read_res = connection.read_tls(&mut cursor);

    // Check how many bytes rustls actually consumed
    let consumed = cursor.position() as usize;
    let len = b.buf_len();

    if consumed == len {
        b.clear();
    } else {
        // Shift leftover, unconsumed ciphertext to the front
        b.copy_within(consumed .. len, 0);
        unsafe { b.set_len(len - consumed) };
    }

    *read_buf = Some(b);

    read_res?;

    connection
        .process_new_packets()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(())
}

/// Attempts to read decoded plaintext from `rustls`.
/// Returns `Ok(BufResult)` if data is yielded, or `Err(B)` if more network data
/// is needed.
pub(crate) fn read_plaintext<C, SD, B: IoBufMut>(connection: &mut C, mut buf: B) -> Result<BufResult<usize, B>, B>
where
    C: DerefMut<Target = ConnectionCommon<SD>>,
    SD: SideData,
{
    let init_len = buf.buf_len();
    let cap = buf.buf_capacity();

    if init_len == cap {
        return Ok(BufResult(Ok(0), buf));
    }

    let slice = unsafe { std::slice::from_raw_parts_mut(buf.buf_mut_ptr().cast::<u8>().add(init_len), cap - init_len) };

    match connection.reader().read(slice) {
        | Ok(n) if n > 0 => unsafe {
            buf.advance_to(init_len + n);
            Ok(BufResult(Ok(n), buf))
        },
        | Err(e) if e.kind() != io::ErrorKind::WouldBlock => Ok(BufResult(Err(e), buf)),
        | _ => Err(buf), // Need more data from the socket
    }
}
