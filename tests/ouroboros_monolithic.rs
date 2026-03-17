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

        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        // Server Read
        let buf = Vec::with_capacity(15);
        let (..) = tls_stream.read_exact(buf).await.unwrap();

        // Server Write
        let (..) = tls_stream.write_all("Pong Monolithic").await.unwrap();
        tls_stream.shutdown().await.expect("(Server) TLS stream shutdown error");
    });

    let client_task = compio::runtime::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = TlsConnector::new(client_config);

        let domain = ServerName::try_from("localhost").unwrap().to_owned();
        let mut tls_stream = connector.connect(domain, stream).await.unwrap();

        // Client Write
        let (..) = tls_stream.write_all("Ping Monolithic").await.unwrap();

        // Client Read
        let buf = Vec::with_capacity(15);
        let (_, read_buf) = tls_stream.read_exact(buf).await.unwrap();
        assert_eq!(read_buf.as_slice(), b"Pong Monolithic");

        tls_stream.shutdown().await.expect("(Client) TLS stream shutdown error");
    });

    let (server_res, client_res) = futures_util::join!(server_task, client_task);
    server_res.expect("(Server) Task error");
    client_res.expect("(Client) Task error");

    Ok(())
}
