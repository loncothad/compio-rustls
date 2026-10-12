use std::{
    cell::RefCell,
    io::{self, Cursor, Read},
    rc::Rc,
    task::Waker,
};

use compio_buf::{BufResult, IoBuf};
use compio_io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_util::FutureExt;

use super::{Response, connection_pair, response};
use crate::split_tls_stream_with_capacity;

struct Control {
    writes_left: Option<usize>,
    max_write: usize,
    next_error: Option<io::ErrorKind>,
    allow_flush: bool,
    allow_shutdown: bool,
    ciphertext: Vec<u8>,
    waker: Option<Waker>,
}

impl Default for Control {
    fn default() -> Self {
        Self {
            writes_left: None,
            max_write: usize::MAX,
            next_error: None,
            allow_flush: true,
            allow_shutdown: true,
            ciphertext: Vec::new(),
            waker: None,
        }
    }
}

struct ControlledWriter(Rc<RefCell<Control>>);

impl AsyncWrite for ControlledWriter {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        std::future::poll_fn(|cx| {
            let mut control = self.0.borrow_mut();
            if control.writes_left == Some(0) {
                control.waker = Some(cx.waker().clone());
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(())
        })
        .await;
        let mut control = self.0.borrow_mut();
        if let Some(left) = &mut control.writes_left {
            *left -= 1;
        }
        if let Some(kind) = control.next_error.take() {
            return BufResult(Err(io::Error::from(kind)), buf);
        }
        let count = control.max_write.min(buf.buf_len());
        control.ciphertext.extend_from_slice(&buf.as_init()[..count]);
        BufResult(Ok(count), buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut control = self.0.borrow_mut();
            if control.allow_flush {
                return std::task::Poll::Ready(Ok(()));
            }
            control.waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        })
        .await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        std::future::poll_fn(|cx| {
            let mut control = self.0.borrow_mut();
            if control.allow_shutdown {
                return std::task::Poll::Ready(Ok(()));
            }
            control.waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        })
        .await
    }
}

fn unblock(control: &Rc<RefCell<Control>>) {
    let mut control = control.borrow_mut();
    control.writes_left = None;
    control.allow_flush = true;
    control.allow_shutdown = true;
    if let Some(waker) = control.waker.take() {
        waker.wake();
    }
}

#[test]
fn reader_progresses_during_blocked_write() {
    let (client, transport, expected) = response(false);
    let control = Rc::new(RefCell::new(Control {
        writes_left: Some(0),
        ..Control::default()
    }));
    let (mut reader, mut writer) =
        split_tls_stream_with_capacity(transport, ControlledWriter(Rc::clone(&control)), client, 128 * 1024);
    let mut writing = Box::pin(writer.write(b"request".to_vec()));
    assert!(
        writing.as_mut().now_or_never().is_none(),
        "transport write must be blocked"
    );
    let (_, actual) = reader
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("reader must progress while the writer is blocked")
        .unwrap();
    assert_eq!(actual, expected);
    unblock(&control);
    writing.now_or_never().expect("writer must resume").unwrap();
}

#[test]
fn reader_progresses_during_transport_flush() {
    let (client, transport, expected) = response(false);
    let control = Rc::new(RefCell::new(Control {
        allow_flush: false,
        ..Control::default()
    }));
    let (mut reader, mut writer) =
        split_tls_stream_with_capacity(transport, ControlledWriter(Rc::clone(&control)), client, 128 * 1024);
    let mut flushing = Box::pin(writer.flush());
    assert!(
        flushing.as_mut().now_or_never().is_none(),
        "transport flush must be blocked"
    );
    let (_, actual) = reader
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("reader must progress during transport flush")
        .unwrap();
    assert_eq!(actual, expected);
    unblock(&control);
    flushing.now_or_never().expect("flush must resume").unwrap();
}

#[test]
fn reader_progresses_during_transport_shutdown() {
    let (client, transport, expected) = response(false);
    let control = Rc::new(RefCell::new(Control {
        allow_shutdown: false,
        ..Control::default()
    }));
    let (mut reader, mut writer) =
        split_tls_stream_with_capacity(transport, ControlledWriter(Rc::clone(&control)), client, 128 * 1024);
    let mut shutting_down = Box::pin(writer.shutdown());
    assert!(
        shutting_down.as_mut().now_or_never().is_none(),
        "transport shutdown must be blocked"
    );
    let (_, actual) = reader
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("reader must progress during transport shutdown")
        .unwrap();
    assert_eq!(actual, expected);
    unblock(&control);
    shutting_down.now_or_never().expect("shutdown must resume").unwrap();
}

#[test]
fn cancelled_partial_write_cannot_replay_ciphertext() {
    let (client, transport, expected) = response(false);
    let control = Rc::new(RefCell::new(Control {
        writes_left: Some(1),
        max_write: 7,
        ..Control::default()
    }));
    let (mut reader, mut writer) =
        split_tls_stream_with_capacity(transport, ControlledWriter(Rc::clone(&control)), client, 128 * 1024);
    let mut writing = Box::pin(writer.write(b"request".to_vec()));
    assert!(
        writing.as_mut().now_or_never().is_none(),
        "second transport write must be blocked"
    );
    assert_eq!(control.borrow().ciphertext.len(), 7);
    drop(writing);
    unblock(&control);
    let (_, actual) = reader
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("reader must remain available after writer cancellation")
        .unwrap();
    assert_eq!(actual, expected);
    let error = writer
        .flush()
        .now_or_never()
        .expect("cancelled writer must fail immediately")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let BufResult(result, _) = writer
        .write_all(b"another request".to_vec())
        .now_or_never()
        .expect("cancelled writer must reject more plaintext");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    let error = writer
        .shutdown()
        .now_or_never()
        .expect("cancelled shutdown must fail immediately")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        control.borrow().ciphertext.len(),
        7,
        "unknown bytes must never be replayed"
    );
}

#[test]
fn errors_and_partial_writes_preserve_record_order() {
    let (client, mut server) = connection_pair();
    let control = Rc::new(RefCell::new(Control {
        writes_left: Some(1),
        max_write: 7,
        ..Control::default()
    }));
    let (_reader, mut writer) = split_tls_stream_with_capacity(
        Response { ciphertext: None },
        ControlledWriter(Rc::clone(&control)),
        client,
        4096,
    );
    let mut writing = Box::pin(writer.write(b"first".to_vec()));
    assert!(
        writing.as_mut().now_or_never().is_none(),
        "second transport write must be blocked"
    );
    assert_eq!(control.borrow().ciphertext.len(), 7);
    control.borrow_mut().next_error = Some(io::ErrorKind::WouldBlock);
    unblock(&control);
    let BufResult(result, _) = writing.now_or_never().expect("write must finish with an error");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    writer
        .write(b"second".to_vec())
        .now_or_never()
        .expect("retry must finish")
        .unwrap();
    let mut ciphertext = Cursor::new(control.borrow().ciphertext.clone());
    while ciphertext.position() < ciphertext.get_ref().len() as u64 {
        server.read_tls(&mut ciphertext).unwrap();
        server.process_new_packets().unwrap();
    }
    let mut actual = vec![0; 11];
    server.reader().read_exact(&mut actual).unwrap();
    assert_eq!(actual, b"firstsecond");
}

#[test]
fn zero_write_keeps_ciphertext_for_flush() {
    let (client, mut server) = connection_pair();
    let control = Rc::new(RefCell::new(Control {
        max_write: 0,
        ..Control::default()
    }));
    // Borrowed transports must remain supported without a new 'static bound.
    let mut transport = ControlledWriter(Rc::clone(&control));
    let (_reader, mut writer) =
        split_tls_stream_with_capacity(Response { ciphertext: None }, &mut transport, client, 4096);
    let BufResult(result, _) = writer
        .write(b"request".to_vec())
        .now_or_never()
        .expect("zero write must finish");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
    control.borrow_mut().max_write = 7;
    writer.flush().now_or_never().expect("flush must finish").unwrap();
    let mut ciphertext = Cursor::new(control.borrow().ciphertext.clone());
    while ciphertext.position() < ciphertext.get_ref().len() as u64 {
        server.read_tls(&mut ciphertext).unwrap();
        server.process_new_packets().unwrap();
    }
    let mut actual = [0; 7];
    server.reader().read_exact(&mut actual).unwrap();
    assert_eq!(&actual, b"request");
}

#[test]
fn cancelled_transport_flush_keeps_write_half_usable() {
    let (client, mut server) = connection_pair();
    let control = Rc::new(RefCell::new(Control {
        allow_flush: false,
        ..Control::default()
    }));
    let (_reader, mut writer) = split_tls_stream_with_capacity(
        Response { ciphertext: None },
        ControlledWriter(Rc::clone(&control)),
        client,
        4096,
    );
    writer
        .write(b"first".to_vec())
        .now_or_never()
        .expect("write must finish")
        .unwrap();
    let mut flushing = Box::pin(writer.flush());
    assert!(
        flushing.as_mut().now_or_never().is_none(),
        "transport flush must be blocked"
    );
    drop(flushing);
    unblock(&control);
    writer
        .write(b"second".to_vec())
        .now_or_never()
        .expect("writer must remain usable")
        .unwrap();
    let mut ciphertext = Cursor::new(control.borrow().ciphertext.clone());
    while ciphertext.position() < ciphertext.get_ref().len() as u64 {
        server.read_tls(&mut ciphertext).unwrap();
        server.process_new_packets().unwrap();
    }
    let mut actual = [0; 11];
    server.reader().read_exact(&mut actual).unwrap();
    assert_eq!(&actual, b"firstsecond");
}

#[test]
fn interrupted_transport_write_does_not_duplicate_plaintext() {
    let (client, mut server) = connection_pair();
    let control = Rc::new(RefCell::new(Control {
        next_error: Some(io::ErrorKind::Interrupted),
        max_write: 7,
        ..Control::default()
    }));
    let (_reader, mut writer) = split_tls_stream_with_capacity(
        Response { ciphertext: None },
        ControlledWriter(Rc::clone(&control)),
        client,
        4096,
    );
    writer
        .write_all(b"request".to_vec())
        .now_or_never()
        .expect("write must retry the interrupted OS operation")
        .unwrap();
    let mut ciphertext = Cursor::new(control.borrow().ciphertext.clone());
    while ciphertext.position() < ciphertext.get_ref().len() as u64 {
        server.read_tls(&mut ciphertext).unwrap();
        server.process_new_packets().unwrap();
    }
    let mut actual = [0; 7];
    server.reader().read_exact(&mut actual).unwrap();
    assert_eq!(&actual, b"request");
    assert_eq!(
        server.reader().read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn flush_sends_handshake_output_generated_by_reader() {
    use rustls::{ClientConnection, ServerConnection, pki_types::ServerName};
    let (server_config, client_config) = super::configs::create_configs();
    let mut client = ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    server.read_tls(&mut Cursor::new(hello)).unwrap();
    server.process_new_packets().unwrap();
    let mut flight = Vec::new();
    server.write_tls(&mut flight).unwrap();

    let control = Rc::new(RefCell::new(Control {
        allow_flush: false,
        ..Control::default()
    }));
    let (mut reader, mut writer) = split_tls_stream_with_capacity(
        Response {
            ciphertext: Some(flight),
        },
        ControlledWriter(Rc::clone(&control)),
        client,
        4096,
    );
    let mut flushing = Box::pin(writer.flush());
    assert!(
        flushing.as_mut().now_or_never().is_none(),
        "transport flush must be blocked"
    );
    let mut reading = Box::pin(reader.read(Vec::with_capacity(1)));
    assert!(
        reading.as_mut().now_or_never().is_none(),
        "no application data has arrived"
    );
    unblock(&control);
    flushing.now_or_never().expect("flush must finish").unwrap();
    assert!(
        !control.borrow().ciphertext.is_empty(),
        "reader-generated handshake output must be sent"
    );
    server
        .read_tls(&mut Cursor::new(control.borrow().ciphertext.clone()))
        .unwrap();
    server.process_new_packets().unwrap();
    assert!(
        !server.is_handshaking(),
        "peer must receive the final handshake messages"
    );
}
