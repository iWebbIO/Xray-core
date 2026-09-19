//! Native VLESS `mlkem768x25519plus.native` 1-RTT encrypted sessions.
//!
//! The configured NFS key is X25519 or ML-KEM-768; every connection additionally
//! establishes a fresh hybrid ML-KEM-768 + X25519 PFS secret. These handshakes
//! prove possession of the configured server private key. They do not identify
//! the VLESS user: the runtime must authenticate the inner VLESS request.
//!
//! This profile supports up to eight ordered relay keys, AES/ChaCha negotiation,
//! authenticated padding, and continuous encrypted records. Ticket resumption,
//! XOR disguises and configured fragmented padding schedules
//! are explicitly unsupported. Server ticket lifetime is zero.

mod config;
mod keys;
mod relay;
mod stream;
mod wire;

use std::io;

use rand::rngs::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use config::{ClientConfig, MAX_RELAY_KEYS, ServerConfig};
pub use stream::EncryptedStream;

use super::encryption::{Algorithm, RecordCipher};
use wire::{ClientState, ServerState};

/// Fully authenticated directional record state, including handshake counters.
pub struct Session {
    pub(crate) outbound: RecordCipher,
    pub(crate) inbound: RecordCipher,
    algorithm: Algorithm,
}

impl Session {
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns `(outbound, inbound)` ciphers for a runtime-owned stream adapter.
    pub fn into_ciphers(self) -> (RecordCipher, RecordCipher) {
        (self.outbound, self.inbound)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

/// Perform the native 1-RTT client exchange and return an encrypted byte stream.
/// The caller owns connection and handshake deadlines (for example `timeout`).
pub async fn client_handshake<S>(
    mut stream: S,
    config: &ClientConfig,
) -> io::Result<EncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (state, hello) = ClientState::start(config, &mut OsRng)?;
    stream.write_all(&hello).await?;
    stream.flush().await?;
    let mut prefix = [0; wire::SERVER_PREFIX_LEN];
    stream.read_exact(&mut prefix).await?;
    let finish = state.receive_prefix(&prefix)?;
    let mut padding = vec![0; finish.padding_len()];
    stream.read_exact(&mut padding).await?;
    let session = finish.finish(&padding)?;
    Ok(EncryptedStream::new(stream, session))
}

/// Perform the native 1-RTT server exchange. Keep `config` shared across accepted
/// connections so its bounded replay history is not reset for each connection.
/// A failed exchange must close the connection; there is no plaintext fallback.
pub async fn server_handshake<S>(
    mut stream: S,
    config: &ServerConfig,
) -> io::Result<EncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = vec![0; config.prefix_len() + wire::LENGTH_LEN];
    stream.read_exact(&mut prefix).await?;
    let mut state = ServerState::start(config, &prefix)?;
    let mut pfs = [0; wire::CLIENT_PFS_CIPHERTEXT_LEN];
    stream.read_exact(&mut pfs).await?;
    state.receive_pfs(&pfs)?;
    let mut padding_length = [0; wire::LENGTH_LEN];
    stream.read_exact(&mut padding_length).await?;
    let length = state.receive_padding_length(&padding_length)?;
    let mut padding = vec![0; length];
    stream.read_exact(&mut padding).await?;
    let (session, reply) = state.finish(config, &padding, &mut OsRng)?;
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(EncryptedStream::new(stream, session))
}

#[cfg(test)]
mod tests;
