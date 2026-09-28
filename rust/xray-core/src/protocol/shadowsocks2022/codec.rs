use super::{
    Account, CipherKind, MAX_PADDING_LENGTH, MAX_PAYLOAD_LENGTH, TIMESTAMP_TOLERANCE_SECONDS,
};
use crate::address::{Address, Destination};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, ensure};
use chacha20poly1305::ChaCha20Poly1305;
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

pub(super) const TAG_LENGTH: usize = 16;
pub(super) const REQUEST_FIXED_LENGTH: usize = 11;

pub(super) fn subkey(account: &Account, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        salt.len() == account.kind.key_len(),
        "invalid Shadowsocks2022 salt length"
    );
    let mut material = Zeroizing::new(Vec::with_capacity(account.key.len() + salt.len()));
    material.extend_from_slice(&account.key);
    material.extend_from_slice(salt);
    let derived = Zeroizing::new(blake3::derive_key(
        "shadowsocks 2022 session subkey",
        &material,
    ));
    Ok(Zeroizing::new(derived[..account.kind.key_len()].to_vec()))
}

enum AeadKind {
    A128(Box<Aes128Gcm>),
    A256(Box<Aes256Gcm>),
    /// IETF ChaCha20-Poly1305: sing's TCP constructor for the chacha
    /// method (12-byte nonce, zero-start, incremented per chunk); only the
    /// UDP layout uses XChaCha (`chacha20poly1305.NewX`).
    ChaCha(Box<ChaCha20Poly1305>),
}
pub(super) struct Cipher {
    aead: AeadKind,
    nonce: [u8; 24],
    nonce_len: usize,
    exhausted: bool,
}
impl Cipher {
    pub(super) fn new(account: &Account, salt: &[u8]) -> Result<Self> {
        let key = subkey(account, salt)?;
        let (aead, nonce_len) = match account.kind {
            CipherKind::Aes128Gcm => (
                AeadKind::A128(Box::new(
                    Aes128Gcm::new_from_slice(&key).expect("fixed key"),
                )),
                12,
            ),
            CipherKind::Aes256Gcm => (
                AeadKind::A256(Box::new(
                    Aes256Gcm::new_from_slice(&key).expect("fixed key"),
                )),
                12,
            ),
            CipherKind::ChaCha20Poly1305 => (
                AeadKind::ChaCha(Box::new(
                    ChaCha20Poly1305::new_from_slice(&key).expect("fixed key"),
                )),
                12,
            ),
        };
        Ok(Self {
            aead,
            nonce: [0; 24],
            nonce_len,
            exhausted: false,
        })
    }
    fn nonce(&self) -> [u8; 24] {
        self.nonce
    }
    fn advance(&mut self) {
        // sing increments only the method's nonce bytes; AES caps at 12.
        for byte in &mut self.nonce[..self.nonce_len] {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                return;
            }
        }
        self.exhausted = true;
    }
    pub(super) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!self.exhausted, "Shadowsocks2022 nonce exhausted");
        let nonce = self.nonce();
        let output = match &self.aead {
            AeadKind::A128(aes) => aes.encrypt((&nonce[..self.nonce_len]).into(), plaintext),
            AeadKind::A256(aes) => aes.encrypt((&nonce[..self.nonce_len]).into(), plaintext),
            AeadKind::ChaCha(cipher) => {
                cipher.encrypt((&nonce[..self.nonce_len]).into(), plaintext)
            }
        }
        .map_err(|_| anyhow::anyhow!("Shadowsocks2022 encryption failed"))?;
        self.advance();
        Ok(output)
    }
    pub(super) fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(!self.exhausted, "Shadowsocks2022 nonce exhausted");
        let nonce = self.nonce();
        let output = match &self.aead {
            AeadKind::A128(aes) => aes.decrypt((&nonce[..self.nonce_len]).into(), ciphertext),
            AeadKind::A256(aes) => aes.decrypt((&nonce[..self.nonce_len]).into(), ciphertext),
            AeadKind::ChaCha(cipher) => {
                cipher.decrypt((&nonce[..self.nonce_len]).into(), ciphertext)
            }
        }
        .map_err(|_| anyhow::anyhow!("Shadowsocks2022 authentication failed"))?;
        self.advance();
        Ok(output)
    }
    pub(super) fn frame(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            payload.len() <= MAX_PAYLOAD_LENGTH,
            "Shadowsocks2022 record exceeds 65535 bytes"
        );
        let mut wire = self.seal(&(payload.len() as u16).to_be_bytes())?;
        wire.extend(self.seal(payload)?);
        Ok(wire)
    }
}

pub(super) fn check_timestamp(timestamp: u64, now: u64) -> Result<()> {
    ensure!(
        timestamp <= i64::MAX as u64 && now.abs_diff(timestamp) <= TIMESTAMP_TOLERANCE_SECONDS,
        "Shadowsocks2022 timestamp outside 30-second window"
    );
    Ok(())
}

pub(super) async fn request(
    account: &Account,
    salt: &[u8],
    target: &Destination,
    padding: &[u8],
    payload: &[u8],
    now: u64,
) -> Result<(Vec<u8>, Cipher)> {
    ensure!(target.port != 0, "Shadowsocks2022 destination port is zero");
    ensure!(
        padding.len() <= MAX_PADDING_LENGTH,
        "Shadowsocks2022 sender padding exceeds 900 bytes"
    );
    ensure!(
        !padding.is_empty() || !payload.is_empty(),
        "Shadowsocks2022 request requires padding or payload"
    );
    let mut variable = Vec::new();
    target.write_socks(&mut variable).await?;
    variable.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    variable.extend_from_slice(padding);
    variable.extend_from_slice(payload);
    ensure!(
        variable.len() <= MAX_PAYLOAD_LENGTH,
        "Shadowsocks2022 variable header too large"
    );
    let mut fixed = vec![0];
    fixed.extend_from_slice(&now.to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    let mut cipher = Cipher::new(account, salt)?;
    let mut wire = salt.to_vec();
    wire.extend(cipher.seal(&fixed)?);
    wire.extend(cipher.seal(&variable)?);
    Ok((wire, cipher))
}

pub(super) fn parse_request_fixed(plaintext: &[u8], now: u64) -> Result<usize> {
    ensure!(
        plaintext.len() == REQUEST_FIXED_LENGTH && plaintext[0] == 0,
        "invalid Shadowsocks2022 client header type/length"
    );
    check_timestamp(
        u64::from_be_bytes(plaintext[1..9].try_into().expect("fixed timestamp")),
        now,
    )?;
    let length = usize::from(u16::from_be_bytes(
        plaintext[9..11].try_into().expect("fixed length"),
    ));
    ensure!(length != 0, "empty Shadowsocks2022 variable header");
    Ok(length)
}

pub(super) async fn parse_request_variable(plaintext: &[u8]) -> Result<(Destination, Vec<u8>)> {
    let mut reader = plaintext;
    let mut destination = Destination::read_socks(&mut reader)
        .await
        .context("Shadowsocks2022 destination")?;
    // sing metadata normalizes IP literals in domain fields, including bracketed
    // IPv6, and unwraps IPv4-mapped IPv6 in either address encoding.
    if let Address::Domain(host) = &destination.address {
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = host.parse() {
            destination.address = Address::Ip(ip);
        }
    }
    if let Address::Ip(std::net::IpAddr::V6(ip)) = destination.address
        && let Some(ip) = ip.to_ipv4_mapped()
    {
        destination.address = Address::Ip(ip.into());
    }
    ensure!(
        destination.port != 0,
        "Shadowsocks2022 destination port is zero"
    );
    let padding = usize::from(
        reader
            .read_u16()
            .await
            .context("Shadowsocks2022 padding length")?,
    );
    ensure!(reader.len() >= padding, "Shadowsocks2022 truncated padding");
    ensure!(
        padding != 0 || !reader.is_empty(),
        "Shadowsocks2022 request requires padding or payload"
    );
    Ok((destination, reader[padding..].to_vec()))
}

pub(super) fn response(
    account: &Account,
    salt: &[u8],
    request_salt: &[u8],
    payload: &[u8],
    now: u64,
) -> Result<(Vec<u8>, Cipher)> {
    ensure!(
        request_salt.len() == account.kind.key_len(),
        "invalid request salt length"
    );
    ensure!(
        !bool::from(salt.ct_eq(request_salt)),
        "response salt must differ from request salt"
    );
    ensure!(
        payload.len() <= MAX_PAYLOAD_LENGTH,
        "Shadowsocks2022 first response too large"
    );
    let mut fixed = vec![1];
    fixed.extend_from_slice(&now.to_be_bytes());
    fixed.extend_from_slice(request_salt);
    fixed.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    let mut cipher = Cipher::new(account, salt)?;
    let mut wire = salt.to_vec();
    wire.extend(cipher.seal(&fixed)?);
    // The pinned client's ReadWithLength(0) still authenticates an empty tag.
    wire.extend(cipher.seal(payload)?);
    Ok((wire, cipher))
}

pub(super) fn parse_response_fixed(
    plaintext: &[u8],
    request_salt: &[u8],
    now: u64,
) -> Result<usize> {
    let end = 9 + request_salt.len();
    ensure!(
        plaintext.len() == end + 2 && plaintext[0] == 1,
        "invalid Shadowsocks2022 server header type/length"
    );
    check_timestamp(
        u64::from_be_bytes(plaintext[1..9].try_into().expect("fixed timestamp")),
        now,
    )?;
    ensure!(
        bool::from(plaintext[9..end].ct_eq(request_salt)),
        "Shadowsocks2022 response is bound to a different request salt"
    );
    Ok(usize::from(u16::from_be_bytes(
        plaintext[end..].try_into().expect("fixed length"),
    )))
}
