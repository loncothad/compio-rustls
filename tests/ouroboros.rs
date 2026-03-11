use std::sync::Arc;

use compio::{
    BufResult,
    net::{
        TcpListener,
        TcpStream,
    },
};
use compio_buf::IoBuf as _;
use compio_io::{
    AsyncRead as _,
    AsyncWrite as _,
};
use compio_rustls::{
    client::TlsConnector,
    server::TlsAcceptor,
};
use rustls::{
    ClientConfig,
    ServerConfig,
};
use rustls_pki_types::ServerName;

fn setup_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn generate_test_certs() -> (
    rustls_pki_types::CertificateDer<'static>,
    rustls_pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

#[compio::test]
async fn client_server_integration() {
    setup_crypto_provider();

    let (cert_der, key_der) = generate_test_certs();

    // Setup Server Config
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("Failed to build server config"),
    );

    // Setup Client Config
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).expect("Failed to add root cert");
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    // Bind Listener
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");

    // Spawn Server Task
    let server_task = compio::runtime::spawn(async move {
        let (stream, _) = listener.accept().await.expect("Failed to accept");
        let acceptor = TlsAcceptor::new(server_config);

        let mut tls_stream = acceptor.accept(stream).await.expect("Server TLS handshake failed");

        // Read from client
        let buf = Vec::with_capacity(1024);
        let BufResult(res, buf) = tls_stream.read(buf).await;
        let n = res.expect("Server read failed");
        assert_eq!(&buf.as_init()[.. n], b"HELLO SERVER");

        // Write to client
        let write_buf = Vec::from("HELLO CLIENT");
        let BufResult(res, _) = tls_stream.write(write_buf).await;
        res.expect("Server write failed");

        tls_stream.flush().await.expect("Server flush failed");
        tls_stream.shutdown().await.expect("Server shutdown failed");
    });

    // Spawn Client Task
    let client_task = compio::runtime::spawn(async move {
        let stream = TcpStream::connect(&addr).await.expect("Client failed to connect");

        let connector = TlsConnector::new(client_config);
        let domain = ServerName::try_from("localhost").expect("Invalid DNS name").to_owned();

        let mut tls_stream = connector
            .connect(domain, stream)
            .await
            .expect("Client TLS handshake failed");

        // Write to server
        let write_buf = Vec::from("HELLO SERVER");
        let BufResult(res, _) = tls_stream.write(write_buf).await;
        res.expect("Client write failed");
        tls_stream.flush().await.expect("Client flush failed");

        // Read from server
        let buf = Vec::with_capacity(1024);
        let BufResult(res, buf) = tls_stream.read(buf).await;
        let n = res.expect("Client read failed");
        assert_eq!(&buf.as_init()[.. n], b"HELLO CLIENT");
    });

    // Await Completion
    let (server_res, client_res) = futures_util::future::join(server_task, client_task).await;
    server_res.expect("Server task panicked");
    client_res.expect("Client task panicked");
}
