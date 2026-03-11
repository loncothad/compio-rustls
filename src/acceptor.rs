use std::{
    io,
    sync::Arc,
};

use compio_io::{
    AsyncRead,
    AsyncWrite,
};
use rustls::{
    ServerConfig,
    ServerConnection,
};

use crate::stream::TlsStream;

/// A wrapper around a [`rustls::ServerConfig`].
///
/// **Note:** Clones are cheap.
#[derive(Clone)]
pub struct TlsAcceptor {
    rustls_server_config: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn new(rustls_server_config: Arc<ServerConfig>) -> Self {
        Self {
            rustls_server_config,
        }
    }

    pub async fn accept<S>(&self, stream: S) -> io::Result<TlsStream<S, ServerConnection>>
    where
        S: AsyncRead + AsyncWrite,
    {
        let session = ServerConnection::new(self.rustls_server_config.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let mut tls_stream = TlsStream::new(stream, session);
        tls_stream.handshake().await?;

        Ok(tls_stream)
    }

    pub async fn accept_with<S, F>(&self, stream: S, f: F) -> io::Result<TlsStream<S, ServerConnection>>
    where
        S: AsyncRead + AsyncWrite,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = ServerConnection::new(self.rustls_server_config.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        f(&mut session);

        let mut tls_stream = TlsStream::new(stream, session);
        tls_stream.handshake().await?;

        Ok(tls_stream)
    }

    /// Get a read-only reference to underlying config
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.rustls_server_config
    }
}
