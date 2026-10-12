use std::io::{self, Cursor, Write};

use compio_buf::{BufResult, IoBuf, IoBufMut};
use compio_io::{AsyncRead, AsyncReadExt, AsyncWrite};
use futures_util::FutureExt;
use rustls::{ClientConnection, ServerConnection, pki_types::ServerName};

use super::{TlsStream, split_tls_stream_with_capacity};

#[path = "../../tests/common/rustls.rs"]
mod configs;

// A peer that sends its entire response in one read and then remains open.
struct Response {
    ciphertext: Option<Vec<u8>>,
}

impl AsyncRead for Response {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let Some(ciphertext) = self.ciphertext.take() else {
            return std::future::pending().await;
        };
        assert!(
            ciphertext.len() <= buf.buf_capacity(),
            "response must fit in one transport read"
        );
        // SAFETY: the destination has sufficient capacity and the source is initialized.
        unsafe {
            std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), buf.buf_mut_ptr().cast(), ciphertext.len());
            buf.set_len(ciphertext.len());
        }
        BufResult(Ok(ciphertext.len()), buf)
    }
}

impl AsyncWrite for Response {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        BufResult(Ok(buf.buf_len()), buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl compio_io::util::Splittable for Response {
    type ReadHalf = Self;
    type WriteHalf = Self;

    fn split(self) -> (Self, Self) {
        (self, Self { ciphertext: None })
    }
}

fn connection_pair() -> (ClientConnection, ServerConnection) {
    let (server_config, client_config) = configs::create_configs();
    let mut client = ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    while client.is_handshaking() || server.is_handshaking() || client.wants_write() || server.wants_write() {
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            server.read_tls(&mut Cursor::new(bytes)).unwrap();
            server.process_new_packets().unwrap();
        }
        let mut bytes = Vec::new();
        server.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            client.read_tls(&mut Cursor::new(bytes)).unwrap();
            client.process_new_packets().unwrap();
        }
    }
    (client, server)
}

fn response(close: bool) -> (ClientConnection, Response, Vec<u8>) {
    let (client, mut server) = connection_pair();
    // More than Rustls's ciphertext intake limit, spread across multiple records.
    let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    server.set_buffer_limit(None);
    server.writer().write_all(&plaintext).unwrap();
    if close {
        server.send_close_notify();
    }
    let mut ciphertext = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut ciphertext).unwrap();
    }
    (
        client,
        Response {
            ciphertext: Some(ciphertext),
        },
        plaintext,
    )
}

#[test]
fn monolithic_coalesced_response() {
    let (client, transport, expected) = response(false);
    let mut stream = TlsStream::with_capacity(transport, client, 128 * 1024);
    let result = stream
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("buffered ciphertext must be processed without waiting for another transport read");
    let (_, actual) = result.unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn split_coalesced_response() {
    let (client, transport, expected) = response(false);
    let (mut reader, _writer) =
        split_tls_stream_with_capacity(transport, Response { ciphertext: None }, client, 128 * 1024);
    let result = reader
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("buffered ciphertext must be processed without waiting for another transport read");
    let (_, actual) = result.unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn coalesced_close_notify() {
    let (client, transport, expected) = response(true);
    let mut stream = TlsStream::with_capacity(transport, client, 128 * 1024);
    let (_, actual) = stream
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("response must not stall")
        .unwrap();
    assert_eq!(actual, expected);
    let BufResult(result, _) = stream
        .read(Vec::with_capacity(1))
        .now_or_never()
        .expect("buffered close_notify must not wait for transport EOF");
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn split_coalesced_close_notify() {
    let (client, transport, expected) = response(true);
    let (mut reader, _writer) =
        split_tls_stream_with_capacity(transport, Response { ciphertext: None }, client, 128 * 1024);
    let (_, actual) = reader
        .read_exact(Vec::with_capacity(expected.len()))
        .now_or_never()
        .expect("response must not stall")
        .unwrap();
    assert_eq!(actual, expected);
    let BufResult(result, _) = reader
        .read(Vec::with_capacity(1))
        .now_or_never()
        .expect("buffered close_notify must not wait for transport EOF");
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn handshake_sends_final_flight() {
    let (server_config, client_config) = configs::create_configs();
    let mut client = ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    server.read_tls(&mut Cursor::new(hello)).unwrap();
    server.process_new_packets().unwrap();
    let mut flight = Vec::new();
    server.write_tls(&mut flight).unwrap();
    let mut stream = TlsStream::new(
        Response {
            ciphertext: Some(flight),
        },
        client,
    );
    stream
        .handshake()
        .now_or_never()
        .expect("handshake must complete")
        .unwrap();
    assert!(
        !stream.get_ref().1.wants_write(),
        "final handshake flight must reach the transport before returning"
    );
}

#[test]
fn splitting_preserves_buffered_ciphertext() {
    let (client, transport, expected) = response(false);
    let mut stream = TlsStream::with_capacity(transport, client, 128 * 1024);
    let (_, first) = stream
        .read(Vec::with_capacity(1))
        .now_or_never()
        .expect("first byte must be available")
        .unwrap();
    assert_eq!(first, expected[..1]);
    let (mut reader, _writer) = stream.into_split();
    let (_, rest) = reader
        .read_exact(Vec::with_capacity(expected.len() - 1))
        .now_or_never()
        .expect("splitting must retain ciphertext already read from the transport")
        .unwrap();
    assert_eq!(rest, expected[1..]);
}

struct BlockedTransport;

impl AsyncRead for BlockedTransport {
    async fn read<B: IoBufMut>(&mut self, _buf: B) -> BufResult<usize, B> {
        std::future::pending().await
    }
}

impl AsyncWrite for BlockedTransport {
    async fn write<B: IoBuf>(&mut self, _buf: B) -> BufResult<usize, B> {
        std::future::pending().await
    }
    async fn flush(&mut self) -> io::Result<()> {
        std::future::pending().await
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        std::future::pending().await
    }
}

fn closed_client_with_pending_write() -> ClientConnection {
    use std::io::Read;
    let (mut client, transport, _) = response(true);
    let mut ciphertext = Cursor::new(transport.ciphertext.unwrap());
    while ciphertext.position() < ciphertext.get_ref().len() as u64 {
        client.read_tls(&mut ciphertext).unwrap();
        client.process_new_packets().unwrap();
        let mut plaintext = [0; 16 * 1024];
        while matches!(client.reader().read(&mut plaintext), Ok(n) if n > 0) {}
    }
    assert!(!client.wants_read(), "client must have received close_notify");
    client.writer().write_all(b"pending write").unwrap();
    client
}

#[test]
fn monolithic_clean_eof_does_not_wait_for_writes() {
    let mut stream = TlsStream::new(BlockedTransport, closed_client_with_pending_write());
    let BufResult(result, _) = stream
        .read(Vec::with_capacity(1))
        .now_or_never()
        .expect("clean EOF must not wait for a blocked outbound write");
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn split_clean_eof_does_not_wait_for_writes() {
    let (mut reader, _writer) =
        super::split_tls_stream(BlockedTransport, BlockedTransport, closed_client_with_pending_write());
    let BufResult(result, _) = reader
        .read(Vec::with_capacity(1))
        .now_or_never()
        .expect("clean EOF must not wait for a blocked outbound write");
    assert_eq!(result.unwrap(), 0);
}

mod split_writes;
