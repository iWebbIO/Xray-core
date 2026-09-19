//! Native relay-chain binding from `proxy/vless/encryption/{client,server}.go`.
//! Each intermediate NFS secret masks the next public-key hash (32 bytes), then
//! continues the same CTR stream over the next relay's first 32 bytes. No XOR
//! disguise is applied in native mode. The last NFS secret keys the hybrid flight.

use std::io;

use aes_gcm::aes::{
    Aes256,
    cipher::{BlockEncrypt, KeyInit},
};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::super::derive_key;
use super::{
    invalid,
    keys::{PrivateKey, PublicKey},
};

struct RelayCtr {
    cipher: Aes256,
    counter: [u8; 16],
    stream: [u8; 16],
    position: usize,
    used: usize,
}

impl RelayCtr {
    fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        let key = Zeroizing::new(derive_key(b"VLESS", key));
        Self {
            cipher: Aes256::new((&*key).into()),
            counter: *iv,
            stream: [0; 16],
            position: 16,
            used: 0,
        }
    }

    fn apply(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        // Native chain binding consumes exactly two 32-byte spans. A numeric
        // carry is allowed: IV=all-FF correctly continues with counter zero.
        if bytes.len() > 64 - self.used {
            return Err(invalid("VLESS relay mask exceeds its two binding spans"));
        }
        self.used += bytes.len();
        for byte in bytes {
            if self.position == 16 {
                let mut block = self.counter.into();
                self.cipher.encrypt_block(&mut block);
                self.stream.copy_from_slice(&block);
                self.position = 0;
                for value in self.counter.iter_mut().rev() {
                    *value = value.wrapping_add(1);
                    if *value != 0 {
                        break;
                    }
                }
            }
            *byte ^= self.stream[self.position];
            self.position += 1;
        }
        Ok(())
    }
}

pub(super) fn client_exchange(
    keys: &[PublicKey],
    iv: &[u8; 16],
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    if keys.is_empty() {
        return Err(invalid("empty VLESS relay key chain"));
    }
    let mut relays = Vec::new();
    let mut previous: Option<RelayCtr> = None;
    for (index, key) in keys.iter().enumerate() {
        let (mut share, nfs_key) = key.exchange(rng)?;
        if let Some(ctr) = previous.as_mut() {
            ctr.apply(&mut share[..32])?;
        }
        relays.extend_from_slice(&share);
        if index + 1 == keys.len() {
            return Ok((relays, nfs_key));
        }
        let mut next_hash = *blake3::hash(&keys[index + 1].public_bytes()).as_bytes();
        let mut ctr = RelayCtr::new(nfs_key.as_ref(), iv);
        ctr.apply(&mut next_hash)?;
        relays.extend_from_slice(&next_hash);
        previous = Some(ctr);
    }
    Err(invalid("empty VLESS relay key chain"))
}

pub(super) fn server_exchange(
    keys: &[PrivateKey],
    iv: &[u8; 16],
    encoded: &[u8],
) -> io::Result<Zeroizing<[u8; 32]>> {
    if keys.is_empty() {
        return Err(invalid("empty VLESS relay key chain"));
    }
    let expected = keys.iter().map(PrivateKey::share_len).sum::<usize>() + (keys.len() - 1) * 32;
    if encoded.len() != expected {
        return Err(invalid("invalid VLESS native relay prefix length"));
    }
    let mut relays = encoded.to_vec();
    let mut offset = 0;
    let mut previous: Option<RelayCtr> = None;
    for (index, key) in keys.iter().enumerate() {
        let length = key.share_len();
        if let Some(ctr) = previous.as_mut() {
            ctr.apply(&mut relays[offset..offset + 32])?;
        }
        let nfs_key = key.exchange(&relays[offset..offset + length])?;
        if index + 1 == keys.len() {
            return Ok(nfs_key);
        }
        offset += length;
        let mut ctr = RelayCtr::new(nfs_key.as_ref(), iv);
        ctr.apply(&mut relays[offset..offset + 32])?;
        let expected_hash = blake3::hash(&keys[index + 1].public_bytes());
        if !bool::from(relays[offset..offset + 32].ct_eq(expected_hash.as_bytes())) {
            return Err(invalid("VLESS native relay key hash mismatch"));
        }
        offset += 32;
        previous = Some(ctr);
    }
    Err(invalid("empty VLESS relay key chain"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ctr_keeps_stream_position_and_allows_numeric_counter_carry() {
        let key = b"VLESS relay binding test";
        let iv = [255; 16];
        let mut together = [0; 64];
        RelayCtr::new(key, &iv).apply(&mut together).unwrap();
        let mut split = [0; 64];
        let mut ctr = RelayCtr::new(key, &iv);
        ctr.apply(&mut split[..32]).unwrap();
        ctr.apply(&mut split[32..]).unwrap();
        assert_eq!(together, split);
        assert!(ctr.apply(&mut [0]).is_err());
        let derived = derive_key(b"VLESS", key);
        let cipher = Aes256::new((&derived).into());
        let mut counter = iv;
        for block in together.chunks_exact(16) {
            let mut expected = counter.into();
            cipher.encrypt_block(&mut expected);
            assert_eq!(block, expected.as_slice());
            for byte in counter.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
        }
    }
}
