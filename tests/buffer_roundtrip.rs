//! Large TLS transfers with thread-local completion-I/O buffers.

use std::io;

use compio::net::{
    TcpListener,
    TcpStream,
};
use compio_buf::BufResult;
use compio_io::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
};
use compio_rustls::{
    client::TlsConnector,
    server::TlsAcceptor,
};
use rustls_pki_types::ServerName;

mod common;

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0 .. len).map(|index| (index % 251) as u8 ^ seed).collect()
}

#[compio::test]
async fn large_monolithic_round_trip() -> io::Result<()> {
    let (server_config, client_config) = common::rustls::create_configs();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = compio::runtime::spawn(async move {
        let (transport, _) = listener.accept().await.unwrap();
        let mut stream = TlsAcceptor::new(server_config).accept(transport).await.unwrap();
        let (_, received) = stream.read_exact(Vec::with_capacity(1_048_593)).await.unwrap();
        assert_eq!(received, payload(1_048_593, 3));
        stream.write_all(payload(1_572_871, 5)).await.unwrap();
        stream.shutdown().await.unwrap();
        let BufResult(result, _) = stream.read(Vec::with_capacity(1)).await;
        assert_eq!(result.unwrap(), 0, "client must close the TLS write half");
    });
    let transport = TcpStream::connect(address).await?;
    let mut stream = TlsConnector::new(client_config)
        .connect(ServerName::try_from("localhost").unwrap(), transport)
        .await?;
    stream.write_all(payload(1_048_593, 3)).await.unwrap();
    let (_, received) = stream.read_exact(Vec::with_capacity(1_572_871)).await.unwrap();
    assert_eq!(received, payload(1_572_871, 5));
    stream.shutdown().await?;
    server.await.unwrap();
    Ok(())
}

#[compio::test]
async fn large_split_bidirectional_transfer() -> io::Result<()> {
    let (server_config, client_config) = common::rustls::create_configs();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = compio::runtime::spawn(async move {
        let (transport, _) = listener.accept().await.unwrap();
        let stream = TlsAcceptor::new(server_config).accept(transport).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        let send = async {
            writer.write_all(payload(1_572_871, 5)).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async {
            let (_, received) = reader.read_exact(Vec::with_capacity(1_048_593)).await.unwrap();
            assert_eq!(received, payload(1_048_593, 3));
            let BufResult(result, _) = reader.read(Vec::with_capacity(1)).await;
            assert_eq!(result.unwrap(), 0, "client must close the TLS write half");
        };
        futures_util::join!(send, receive);
    });
    let transport = TcpStream::connect(address).await?;
    let stream = TlsConnector::new(client_config)
        .connect(ServerName::try_from("localhost").unwrap(), transport)
        .await?;
    let (mut reader, mut writer) = stream.into_split();
    let send = async {
        writer.write_all(payload(1_048_593, 3)).await.unwrap();
        writer.shutdown().await.unwrap();
    };
    let receive = async {
        let (_, received) = reader.read_exact(Vec::with_capacity(1_572_871)).await.unwrap();
        assert_eq!(received, payload(1_572_871, 5));
        let BufResult(result, _) = reader.read(Vec::with_capacity(1)).await;
        assert_eq!(result.unwrap(), 0, "server must close the TLS write half");
    };
    futures_util::join!(send, receive);
    server.await.unwrap();
    Ok(())
}
