use std::{io, time::Instant};

use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use super::super::encryption::{Algorithm, MAX_NONCE, RecordCipher, SessionAead};
use super::{ClientConfig, ServerConfig, Session, invalid, keys, relay, unsupported};

pub(super) const LENGTH_LEN: usize = 18;
pub(super) const CLIENT_PFS_CIPHERTEXT_LEN: usize = 1184 + 32 + 16;
pub(super) const SERVER_PFS_CIPHERTEXT_LEN: usize = 1088 + 32 + 16;
pub(super) const SERVER_PREFIX_LEN: usize = SERVER_PFS_CIPHERTEXT_LEN + 32 + LENGTH_LEN;

fn length_bytes(length: usize) -> io::Result<[u8; 2]> {
    Ok(u16::try_from(length)
        .map_err(|_| invalid("VLESS handshake field exceeds u16 length"))?
        .to_be_bytes())
}

fn read_length(plaintext: &[u8]) -> io::Result<usize> {
    let length: [u8; 2] = plaintext
        .try_into()
        .map_err(|_| invalid("invalid VLESS handshake length plaintext"))?;
    Ok(usize::from(u16::from_be_bytes(length)))
}

fn padding_length(plaintext: &[u8]) -> io::Result<usize> {
    let length = read_length(plaintext)?;
    if length < 16 {
        return Err(invalid(
            "VLESS handshake padding is shorter than its authentication tag",
        ));
    }
    Ok(length)
}

fn append_padding(
    aead: &mut SessionAead,
    output: &mut Vec<u8>,
    plaintext_len: usize,
) -> io::Result<()> {
    output.extend(aead.seal(&length_bytes(plaintext_len + 16)?, &[])?);
    output.extend(aead.seal(&vec![0; plaintext_len], &[])?);
    Ok(())
}

pub(super) struct ClientState {
    algorithm: Algorithm,
    nfs_key: Zeroizing<[u8; 32]>,
    nfs_aead: SessionAead,
    ephemeral: keys::Ephemeral,
    client_share: Vec<u8>,
}

impl ClientState {
    pub(super) fn start(
        config: &ClientConfig,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> io::Result<(Self, Vec<u8>)> {
        let iv = keys::random_bytes::<16>(rng)?;
        let (nfs_share, nfs_key) = relay::client_exchange(&config.keys, &iv, rng)?;
        let mut nfs_aead = SessionAead::new(&iv, nfs_key.as_ref(), config.algorithm);
        let ephemeral = keys::Ephemeral::generate(rng)?;
        let client_share = ephemeral.public_bytes();
        let mut hello = Vec::with_capacity(16 + nfs_share.len() + 1268 + config.padding + 16);
        hello.extend_from_slice(&iv);
        hello.extend_from_slice(&nfs_share);
        hello.extend(nfs_aead.seal(&length_bytes(CLIENT_PFS_CIPHERTEXT_LEN)?, &[])?);
        hello.extend(nfs_aead.seal(&client_share, &[])?);
        append_padding(&mut nfs_aead, &mut hello, config.padding)?;
        Ok((
            Self {
                algorithm: config.algorithm,
                nfs_key,
                nfs_aead,
                ephemeral,
                client_share,
            },
            hello,
        ))
    }

    pub(super) fn receive_prefix(mut self, prefix: &[u8]) -> io::Result<ClientFinish> {
        if prefix.len() != SERVER_PREFIX_LEN {
            return Err(invalid("truncated or trailing VLESS server hello prefix"));
        }
        // client.go:159 fails to check this return value. Here the NFS AEAD tag
        // must authenticate before any decapsulation or server key processing.
        let server_share =
            self.nfs_aead
                .open_at(&MAX_NONCE, &prefix[..SERVER_PFS_CIPHERTEXT_LEN], &[])?;
        let mut united = self.ephemeral.shared(&server_share)?;
        united.extend_from_slice(self.nfs_key.as_ref());
        let outbound = SessionAead::new(&self.client_share, &united, self.algorithm);
        let mut inbound = SessionAead::new(&server_share, &united, self.algorithm);
        let ticket_end = SERVER_PFS_CIPHERTEXT_LEN + 32;
        let ticket = inbound.open(&prefix[SERVER_PFS_CIPHERTEXT_LEN..ticket_end], &[])?;
        if ticket.len() != 16 {
            return Err(invalid("invalid VLESS ticket plaintext length"));
        }
        // 1-RTT clients may connect to Go servers offering ticket resumption.
        // Authenticate the ticket but deliberately do not retain or reuse it.
        let length = padding_length(&inbound.open(&prefix[ticket_end..], &[])?)?;
        Ok(ClientFinish {
            algorithm: self.algorithm,
            united,
            outbound,
            inbound,
            padding_len: length,
        })
    }
}

pub(super) struct ClientFinish {
    algorithm: Algorithm,
    united: Zeroizing<Vec<u8>>,
    outbound: SessionAead,
    inbound: SessionAead,
    padding_len: usize,
}

impl ClientFinish {
    pub(super) fn padding_len(&self) -> usize {
        self.padding_len
    }

    pub(super) fn finish(mut self, padding: &[u8]) -> io::Result<Session> {
        if padding.len() != self.padding_len {
            return Err(invalid("truncated or trailing VLESS server padding"));
        }
        self.inbound.open(padding, &[])?;
        Ok(Session {
            outbound: RecordCipher::from_aead(self.outbound, &self.united),
            inbound: RecordCipher::from_aead(self.inbound, &self.united),
            algorithm: self.algorithm,
        })
    }
}

pub(super) struct ServerState {
    algorithm: Algorithm,
    nfs_key: Zeroizing<[u8; 32]>,
    nfs_aead: SessionAead,
    client_share: Option<Vec<u8>>,
    padding_len: Option<usize>,
    transcript: blake3::Hasher,
}

impl ServerState {
    pub(super) fn start(config: &ServerConfig, prefix: &[u8]) -> io::Result<Self> {
        let start = config.prefix_len();
        if prefix.len() != start + LENGTH_LEN {
            return Err(invalid("truncated or trailing VLESS client hello prefix"));
        }
        let iv = prefix[..16]
            .try_into()
            .expect("checked relay prefix length");
        let nfs_key = relay::server_exchange(&config.keys, iv, &prefix[16..start])?;
        let (algorithm, nfs_aead, length) =
            negotiate(&prefix[..16], nfs_key.as_ref(), &prefix[start..])?;
        if length == 32 {
            return Err(unsupported(
                "VLESS 0-RTT tickets are unsupported by this server profile",
            ));
        }
        if length != CLIENT_PFS_CIPHERTEXT_LEN {
            return Err(unsupported(
                "VLESS hybrid hello must contain exactly ML-KEM-768 and X25519 shares",
            ));
        }
        // X25519 admits distinct canonical shares with the same shared key.
        // Relay masks inherit that equivalence, so raw relay bytes cannot name
        // a replay. Bind the effective key and the authenticated flight instead.
        let mut transcript = blake3::Hasher::new_derive_key(
            "xray-core VLESS native 1-RTT authenticated replay identity v1",
        );
        transcript.update(&prefix[..16]);
        transcript.update(nfs_key.as_ref());
        transcript.update(&prefix[start..]);
        Ok(Self {
            algorithm,
            nfs_key,
            nfs_aead,
            client_share: None,
            padding_len: None,
            transcript,
        })
    }

    pub(super) fn receive_pfs(&mut self, ciphertext: &[u8]) -> io::Result<()> {
        if self.client_share.is_some() || ciphertext.len() != CLIENT_PFS_CIPHERTEXT_LEN {
            return Err(invalid("invalid VLESS client key exchange state or length"));
        }
        let share = self.nfs_aead.open(ciphertext, &[])?;
        if share.len() != 1184 + 32 {
            return Err(invalid("invalid VLESS client hybrid share length"));
        }
        self.transcript.update(ciphertext);
        self.client_share = Some(share);
        Ok(())
    }

    pub(super) fn receive_padding_length(&mut self, ciphertext: &[u8]) -> io::Result<usize> {
        if self.client_share.is_none()
            || self.padding_len.is_some()
            || ciphertext.len() != LENGTH_LEN
        {
            return Err(invalid("invalid VLESS client padding state or length"));
        }
        let length = padding_length(&self.nfs_aead.open(ciphertext, &[])?)?;
        self.transcript.update(ciphertext);
        self.padding_len = Some(length);
        Ok(length)
    }

    pub(super) fn finish(
        mut self,
        config: &ServerConfig,
        ciphertext: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> io::Result<(Session, Vec<u8>)> {
        if self.padding_len != Some(ciphertext.len()) {
            return Err(invalid("truncated or trailing VLESS client padding"));
        }
        self.nfs_aead.open(ciphertext, &[])?;
        self.transcript.update(ciphertext);
        let client_share = self
            .client_share
            .take()
            .ok_or_else(|| invalid("missing VLESS client hybrid share"))?;
        // Validate/derive the fresh hybrid secret before committing replay state.
        // No unauthenticated length, partial flight, or malformed key can fill it.
        let (server_share, mut united) = keys::server_hybrid(&client_share, rng)?;
        united.extend_from_slice(self.nfs_key.as_ref());
        config.reserve(*self.transcript.finalize().as_bytes(), Instant::now())?;

        let mut outbound = SessionAead::new(&server_share, &united, self.algorithm);
        let inbound = SessionAead::new(&client_share, &united, self.algorithm);
        let mut ticket = keys::random_bytes::<16>(rng)?;
        ticket[..2].fill(0); // This implementation advertises no ticket resumption.
        let mut hello = self.nfs_aead.seal_at(&MAX_NONCE, &server_share, &[])?;
        hello.extend(outbound.seal(&ticket, &[])?);
        append_padding(&mut outbound, &mut hello, config.padding)?;
        let session = Session {
            outbound: RecordCipher::from_aead(outbound, &united),
            inbound: RecordCipher::from_aead(inbound, &united),
            algorithm: self.algorithm,
        };
        Ok((session, hello))
    }
}

fn negotiate(
    iv: &[u8],
    key: &[u8],
    ciphertext: &[u8],
) -> io::Result<(Algorithm, SessionAead, usize)> {
    for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
        let mut candidate = SessionAead::new(iv, key, algorithm);
        if let Ok(plaintext) = candidate.open(ciphertext, &[]) {
            return Ok((algorithm, candidate, read_length(&plaintext)?));
        }
    }
    Err(invalid("VLESS client hello length authentication failed"))
}
