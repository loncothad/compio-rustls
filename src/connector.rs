use std::{
    io,
    sync::Arc,
};

use compio_io::{
    AsyncRead,
    AsyncWrite,
};
use rustls::{
    ClientConfig,
    ClientConnection,
    pki_types::ServerName,
};

use crate::stream::TlsStream;

/// A wrapper around a [`rustls::ClientConfig`].
///
/// **Note:** Clones are cheap.
#[derive(Clone)]
pub struct TlsConnector {
    rustls_client_config: Arc<ClientConfig>,
}

impl TlsConnector {
    pub fn new(rustls_client_config: Arc<ClientConfig>) -> Self {
        Self {
            rustls_client_config,
        }
    }

    pub async fn connect<S>(&self, domain: ServerName<'static>, stream: S) -> io::Result<TlsStream<S, ClientConnection>>
    where
        S: AsyncRead + AsyncWrite,
    {
        self.connect_impl(domain, stream, None, |_| ()).await
    }

    pub async fn connect_with<S, F>(
        &self,
        domain: ServerName<'static>,
        stream: S,
        f: F,
    ) -> io::Result<TlsStream<S, ClientConnection>>
    where
        S: AsyncRead + AsyncWrite,
        F: FnOnce(&mut ClientConnection),
    {
        self.connect_impl(domain, stream, None, f).await
    }

    async fn connect_impl<S, F>(
        &self,
        domain: ServerName<'static>,
        stream: S,
        alpn_protocols: Option<Vec<Vec<u8>>>,
        f: F,
    ) -> io::Result<TlsStream<S, ClientConnection>>
    where
        S: AsyncRead + AsyncWrite,
        F: FnOnce(&mut ClientConnection),
    {
        let alpn = alpn_protocols.unwrap_or_else(|| self.rustls_client_config.alpn_protocols.clone());
        let mut session = ClientConnection::new_with_alpn(self.rustls_client_config.clone(), domain, alpn)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        f(&mut session);

        let mut tls_stream = TlsStream::new(stream, session);
        tls_stream.handshake().await?;

        Ok(tls_stream)
    }

    pub fn with_alpn(&self, alpn_protocols: Vec<Vec<u8>>) -> TlsConnectorWithAlpn<'_> {
        TlsConnectorWithAlpn {
            inner: self,
            alpn_protocols,
        }
    }

    /// Get a read-only reference to underlying config
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.rustls_client_config
    }
}

pub struct TlsConnectorWithAlpn<'c> {
    inner:          &'c TlsConnector,
    alpn_protocols: Vec<Vec<u8>>,
}

impl<'c> TlsConnectorWithAlpn<'c> {
    pub async fn connect<S>(self, domain: ServerName<'static>, stream: S) -> io::Result<TlsStream<S, ClientConnection>>
    where
        S: AsyncRead + AsyncWrite,
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), |_| ())
            .await
    }

    pub async fn connect_with<S, F>(
        self,
        domain: ServerName<'static>,
        stream: S,
        f: F,
    ) -> io::Result<TlsStream<S, ClientConnection>>
    where
        S: AsyncRead + AsyncWrite,
        F: FnOnce(&mut ClientConnection),
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), f)
            .await
    }
}
