use std::io;

use compio::net::{
    TcpListener,
    TcpStream,
};
use compio_io::{
    AsyncReadExt as _,
    AsyncWrite as _,
    AsyncWriteExt as _,
};
use compio_rustls::{
    client::TlsConnector,
    server::TlsAcceptor,
};
use rustls_pki_types::ServerName;

use crate::common::rustls::create_configs;

mod common;

#[compio::test]
async fn run() -> io::Result<()> {
    let (server_config, client_config) = create_configs();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server_task = compio::runtime::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let acceptor = TlsAcceptor::new(server_config);

        let tls_stream = acceptor.accept(stream).await.unwrap();

        // Split the stream
        let (tcp_stream, rustls_conn) = tls_stream.into_inner();
        let (tcp_rx, tcp_tx) = tcp_stream.into_split();
        let (mut tls_rx, mut tls_tx) = compio_rustls::split_tls_stream(tcp_rx, tcp_tx, rustls_conn);

        // Spawn a parallel write task
        let write_task = compio::runtime::spawn(async move {
            let (..) = tls_tx.write_all(b"Pong Split Msg!".to_vec()).await.unwrap();
            tls_tx.shutdown().await.unwrap();
        });

        // Current task acts as the reader
        let buf = Vec::with_capacity(15);
        let (_, read_buf) = tls_rx.read_exact(buf).await.unwrap();
        assert_eq!(read_buf.as_slice(), b"Ping Split Msg!");

        write_task.await.expect("(Server) Write task error");
    });

    let client_task = compio::runtime::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::new(client_config);

        let domain = ServerName::try_from("localhost").unwrap().to_owned();
        let tls_stream = connector.connect(domain, stream).await.unwrap();

        // Split the stream
        let (tcp_stream, rustls_conn) = tls_stream.into_inner();
        let (tcp_rx, tcp_tx) = tcp_stream.into_split();
        let (mut tls_rx, mut tls_tx) = compio_rustls::split_tls_stream(tcp_rx, tcp_tx, rustls_conn);

        // Spawn a parallel write task
        let write_task = compio::runtime::spawn(async move {
            let (..) = tls_tx.write_all(b"Ping Split Msg!".to_vec()).await.unwrap();
            tls_tx.shutdown().await.unwrap();
        });

        // Current task acts as the reader
        let buf = Vec::with_capacity(15);
        let (_, read_buf) = tls_rx.read_exact(buf).await.unwrap();
        assert_eq!(read_buf.as_slice(), b"Pong Split Msg!");

        write_task.await.expect("(Client) Write task error");
    });

    let (server_res, client_res) = futures_util::join!(server_task, client_task);
    server_res.expect("(Server) Task error");
    client_res.expect("(Client) Task error");

    Ok(())
}
