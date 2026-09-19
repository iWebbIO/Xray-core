use std::io;

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::invalid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    pub(crate) fn from_id(id: u16) -> io::Result<Self> {
        match id {
            0x1301 => Ok(Self::Aes128GcmSha256),
            0x1302 => Ok(Self::Aes256GcmSha384),
            0x1303 => Ok(Self::ChaCha20Poly1305Sha256),
            _ => Err(invalid("server selected an unoffered TLS cipher suite")),
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    pub(crate) fn hash_len(self) -> usize {
        if self == Self::Aes256GcmSha384 {
            48
        } else {
            32
        }
    }

    fn key_len(self) -> usize {
        if self == Self::Aes128GcmSha256 {
            16
        } else {
            32
        }
    }

    pub(crate) fn hash(self, bytes: &[u8]) -> Vec<u8> {
        if self == Self::Aes256GcmSha384 {
            Sha384::digest(bytes).to_vec()
        } else {
            Sha256::digest(bytes).to_vec()
        }
    }

    fn extract(self, salt: &[u8], input: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(if self == Self::Aes256GcmSha384 {
            Hkdf::<Sha384>::extract(Some(salt), input).0.to_vec()
        } else {
            Hkdf::<Sha256>::extract(Some(salt), input).0.to_vec()
        })
    }

    pub(crate) fn expand_label(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        if label.len() + 6 > 255 || context.len() > 255 || len > u16::MAX as usize {
            return Err(invalid("invalid TLS HKDF label length"));
        }
        let mut info = Vec::with_capacity(10 + label.len() + context.len());
        info.extend_from_slice(&(len as u16).to_be_bytes());
        info.push((label.len() + 6) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        let mut output = Zeroizing::new(vec![0; len]);
        if self == Self::Aes256GcmSha384 {
            Hkdf::<Sha384>::from_prk(secret)
                .map_err(|_| invalid("invalid TLS secret"))?
                .expand(&info, &mut output)
                .map_err(|_| invalid("TLS HKDF expansion failed"))?;
        } else {
            Hkdf::<Sha256>::from_prk(secret)
                .map_err(|_| invalid("invalid TLS secret"))?
                .expand(&info, &mut output)
                .map_err(|_| invalid("TLS HKDF expansion failed"))?;
        }
        Ok(output)
    }

    pub(crate) fn finished(
        self,
        traffic_secret: &[u8],
        transcript_hash: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        let key = self.expand_label(traffic_secret, b"finished", b"", self.hash_len())?;
        let result = if self == Self::Aes256GcmSha384 {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&key)
                .map_err(|_| invalid("invalid TLS Finished key"))?;
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        } else {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                .map_err(|_| invalid("invalid TLS Finished key"))?;
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        };
        Ok(Zeroizing::new(result))
    }
}

#[derive(Clone)]
pub(crate) enum Transcript {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Transcript {
    pub(crate) fn new(suite: CipherSuite) -> Self {
        if suite == CipherSuite::Aes256GcmSha384 {
            Self::Sha384(Sha384::new())
        } else {
            Self::Sha256(Sha256::new())
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hash) => hash.update(bytes),
            Self::Sha384(hash) => hash.update(bytes),
        }
    }

    pub(crate) fn hash(&self) -> Vec<u8> {
        match self {
            Self::Sha256(hash) => hash.clone().finalize().to_vec(),
            Self::Sha384(hash) => hash.clone().finalize().to_vec(),
        }
    }
}

pub(crate) struct HandshakeSecrets {
    pub(crate) client: Zeroizing<Vec<u8>>,
    pub(crate) server: Zeroizing<Vec<u8>>,
    master: Zeroizing<Vec<u8>>,
    suite: CipherSuite,
}

impl HandshakeSecrets {
    pub(crate) fn new(
        suite: CipherSuite,
        shared_key: &[u8],
        hello_hash: &[u8],
    ) -> io::Result<Self> {
        let zero = Zeroizing::new(vec![0; suite.hash_len()]);
        let early = suite.extract(&zero, &zero);
        let derived = suite.expand_label(&early, b"derived", &suite.hash(b""), suite.hash_len())?;
        let handshake = suite.extract(&derived, shared_key);
        let client =
            suite.expand_label(&handshake, b"c hs traffic", hello_hash, suite.hash_len())?;
        let server =
            suite.expand_label(&handshake, b"s hs traffic", hello_hash, suite.hash_len())?;
        let derived =
            suite.expand_label(&handshake, b"derived", &suite.hash(b""), suite.hash_len())?;
        let master = suite.extract(&derived, &zero);
        Ok(Self {
            client,
            server,
            master,
            suite,
        })
    }

    pub(crate) fn application(
        &self,
        server_finished_hash: &[u8],
    ) -> io::Result<(RecordCipher, RecordCipher)> {
        let client = self.suite.expand_label(
            &self.master,
            b"c ap traffic",
            server_finished_hash,
            self.suite.hash_len(),
        )?;
        let server = self.suite.expand_label(
            &self.master,
            b"s ap traffic",
            server_finished_hash,
            self.suite.hash_len(),
        )?;
        Ok((
            RecordCipher::new(self.suite, client)?,
            RecordCipher::new(self.suite, server)?,
        ))
    }
}

/// TLS 1.3 traffic keys, including a strictly monotonic per-key record counter.
pub(crate) struct RecordCipher {
    suite: CipherSuite,
    secret: Zeroizing<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
    sequence: u64,
}

impl RecordCipher {
    pub(crate) fn new(suite: CipherSuite, secret: Zeroizing<Vec<u8>>) -> io::Result<Self> {
        if secret.len() != suite.hash_len() {
            return Err(invalid("incorrect TLS traffic-secret length"));
        }
        let key = suite.expand_label(&secret, b"key", b"", suite.key_len())?;
        let iv = suite.expand_label(&secret, b"iv", b"", 12)?;
        Ok(Self {
            suite,
            secret,
            key,
            iv,
            sequence: 0,
        })
    }

    pub(crate) fn needs_update(&self) -> bool {
        self.sequence >= 1 << 20
    }

    pub(crate) fn update(&mut self) -> io::Result<()> {
        let next =
            self.suite
                .expand_label(&self.secret, b"traffic upd", b"", self.suite.hash_len())?;
        *self = Self::new(self.suite, next)?;
        Ok(())
    }

    fn nonce(&self) -> io::Result<[u8; 12]> {
        if self.sequence == u64::MAX {
            return Err(invalid("TLS record sequence exhausted"));
        }
        let mut nonce: [u8; 12] = self
            .iv
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid TLS IV"))?;
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        Ok(nonce)
    }

    pub(crate) fn seal(&mut self, kind: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.seal_padded(kind, payload, 0)
    }

    pub(crate) fn seal_padded(
        &mut self,
        kind: u8,
        payload: &[u8],
        padding_len: usize,
    ) -> io::Result<Vec<u8>> {
        let inner_len = payload
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(padding_len))
            .filter(|&length| length <= 16385)
            .ok_or_else(|| invalid("invalid TLS inner plaintext length"))?;
        if !matches!(kind, 21..=23) || (kind != 23 && payload.is_empty()) {
            return Err(invalid("invalid TLS inner plaintext"));
        }
        let nonce = self.nonce()?;
        let len = inner_len + 16;
        let header = [23, 3, 3, (len >> 8) as u8, len as u8];
        let mut encrypted = payload.to_vec();
        encrypted.push(kind);
        encrypted.resize(inner_len, 0);
        let tag = match self.suite {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid AES key"))?
                .encrypt_in_place_detached((&nonce).into(), &header, &mut encrypted)
                .map(|tag| tag.to_vec()),
            CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid AES key"))?
                .encrypt_in_place_detached((&nonce).into(), &header, &mut encrypted)
                .map(|tag| tag.to_vec()),
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid ChaCha key"))?
                .encrypt_in_place_detached((&nonce).into(), &header, &mut encrypted)
                .map(|tag| tag.to_vec()),
        }
        .map_err(|_| invalid("TLS record encryption failed"))?;
        self.sequence += 1;
        let mut record = Vec::with_capacity(5 + len);
        record.extend_from_slice(&header);
        record.extend_from_slice(&encrypted);
        record.extend_from_slice(&tag);
        Ok(record)
    }

    pub(crate) fn open(
        &mut self,
        header: &[u8; 5],
        mut payload: Vec<u8>,
    ) -> io::Result<(u8, Vec<u8>)> {
        if header[..3] != [23, 3, 3]
            || payload.len() < 17
            || payload.len() > 16640
            || usize::from(u16::from_be_bytes([header[3], header[4]])) != payload.len()
        {
            return Err(invalid("invalid TLS encrypted record"));
        }
        let nonce = self.nonce()?;
        let tag = payload.split_off(payload.len() - 16);
        let result = match self.suite {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid AES key"))?
                .decrypt_in_place_detached(
                    (&nonce).into(),
                    header,
                    &mut payload,
                    tag.as_slice().into(),
                ),
            CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid AES key"))?
                .decrypt_in_place_detached(
                    (&nonce).into(),
                    header,
                    &mut payload,
                    tag.as_slice().into(),
                ),
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid("invalid ChaCha key"))?
                .decrypt_in_place_detached(
                    (&nonce).into(),
                    header,
                    &mut payload,
                    tag.as_slice().into(),
                ),
        };
        result.map_err(|_| invalid("TLS record authentication failed"))?;
        // TLSInnerPlaintext includes the content type and every padding byte.
        // Removing padding first would accept oversized authenticated records.
        if payload.len() > 16385 {
            return Err(invalid("TLS inner plaintext exceeds 2^14 + 1 bytes"));
        }
        let end = payload
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or_else(|| invalid("TLS inner plaintext has no content type"))?;
        let kind = payload[end];
        if end > 16384 || !matches!(kind, 21..=23) || (kind != 23 && end == 0) {
            return Err(invalid("invalid TLS inner content type or length"));
        }
        payload.truncate(end);
        self.sequence += 1;
        Ok((kind, payload))
    }
}

pub(crate) fn verify_finished(expected: &[u8], received: &[u8]) -> io::Result<()> {
    if !bool::from(expected.ct_eq(received)) {
        return Err(invalid("TLS server Finished authentication failed"));
    }
    Ok(())
}
