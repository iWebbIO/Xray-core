//! VLESS encryption record and header-mask primitives from `encryption/common.go`
//! and `encryption/xor.go`. Session key exchange and ticket handling are separate.

use super::derive_key;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
    aes::{Aes256, cipher::BlockEncrypt},
};
use chacha20poly1305::ChaCha20Poly1305;
use std::io;
use zeroize::Zeroizing;

pub const RECORD_HEADER_LEN: usize = 5;
pub const TAG_LEN: usize = 16;
pub const MAX_WRITE_PLAINTEXT: usize = 8192;
pub const MAX_RECORD_CIPHERTEXT: usize = 16640;
pub const MAX_NONCE: [u8; 12] = [255; 12];

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

enum Cipher {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// A directional handshake/session AEAD. The implicit nonce is incremented
/// before use: the first operation uses 000000000000000000000001.
/// An authentication failure permanently poisons this state.
pub struct SessionAead {
    cipher: Cipher,
    nonce: [u8; 12],
    failed: bool,
}

impl SessionAead {
    pub fn new(context: &[u8], key: &[u8], algorithm: Algorithm) -> Self {
        let key = Zeroizing::new(derive_key(context, key));
        let cipher = match algorithm {
            Algorithm::Aes256Gcm => Cipher::Aes(Box::new(Aes256Gcm::new((&*key).into()))),
            Algorithm::ChaCha20Poly1305 => {
                Cipher::ChaCha(Box::new(ChaCha20Poly1305::new((&*key).into())))
            }
        };
        Self {
            cipher,
            nonce: [0; 12],
            failed: false,
        }
    }

    pub fn nonce(&self) -> [u8; 12] {
        self.nonce
    }

    fn next_nonce(&mut self) -> io::Result<[u8; 12]> {
        if self.failed {
            return Err(invalid("VLESS AEAD is poisoned"));
        }
        for byte in self.nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        Ok(self.nonce)
    }

    pub fn seal(&mut self, plaintext: &[u8], additional_data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        self.seal_at(&nonce, plaintext, additional_data)
    }

    pub fn open(&mut self, ciphertext: &[u8], additional_data: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        let result = self.open_at(&nonce, ciphertext, additional_data);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Explicit nonces are used by the pinned key exchange (notably MAX_NONCE).
    /// Caller must ensure nonce uniqueness; this does not advance the counter.
    pub fn seal_at(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(invalid("VLESS AEAD is poisoned"));
        }
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match &self.cipher {
            Cipher::Aes(cipher) => cipher.encrypt(nonce.into(), payload),
            Cipher::ChaCha(cipher) => cipher.encrypt(nonce.into(), payload),
        }
        .map_err(|_| invalid("VLESS AEAD encryption failed"))
    }

    pub fn open_at(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(invalid("VLESS AEAD is poisoned"));
        }
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let result = match &self.cipher {
            Cipher::Aes(cipher) => cipher.decrypt(nonce.into(), payload),
            Cipher::ChaCha(cipher) => cipher.decrypt(nonce.into(), payload),
        }
        .map_err(|_| invalid("VLESS AEAD authentication failed"));
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

pub fn encode_record_header(ciphertext_length: usize) -> io::Result<[u8; 5]> {
    if !(17..=MAX_RECORD_CIPHERTEXT).contains(&ciphertext_length) {
        return Err(invalid("invalid VLESS encrypted record length"));
    }
    let length = (ciphertext_length as u16).to_be_bytes();
    Ok([23, 3, 3, length[0], length[1]])
}

pub fn decode_record_header(header: &[u8]) -> io::Result<usize> {
    if header.len() != 5 || header[..3] != [23, 3, 3] {
        return Err(invalid("invalid VLESS encrypted record header"));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if !(17..=MAX_RECORD_CIPHERTEXT).contains(&length) {
        return Err(invalid("invalid VLESS encrypted record length"));
    }
    Ok(length)
}

/// One direction after the handshake supplies the context and united key.
/// A direction must be used only for sealing or only for opening, never both.
pub struct RecordCipher {
    algorithm: Algorithm,
    united_key: Zeroizing<Vec<u8>>,
    aead: SessionAead,
    failed: bool,
}

impl RecordCipher {
    /// Continue a direction after handshake messages have already consumed
    /// nonces. Resetting this AEAD would reuse a key/nonce pair.
    pub fn from_aead(aead: SessionAead, united_key: &[u8]) -> Self {
        let algorithm = match &aead.cipher {
            Cipher::Aes(_) => Algorithm::Aes256Gcm,
            Cipher::ChaCha(_) => Algorithm::ChaCha20Poly1305,
        };
        let failed = aead.failed;
        Self {
            algorithm,
            united_key: Zeroizing::new(united_key.to_vec()),
            aead,
            failed,
        }
    }

    pub fn new(context: &[u8], united_key: &[u8], algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            united_key: Zeroizing::new(united_key.to_vec()),
            aead: SessionAead::new(context, united_key, algorithm),
            failed: false,
        }
    }

    pub fn seal_record(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(invalid("VLESS record cipher is poisoned"));
        }
        if plaintext.is_empty() || plaintext.len() > MAX_WRITE_PLAINTEXT {
            return Err(invalid("VLESS record plaintext must contain 1..8192 bytes"));
        }
        let header = encode_record_header(plaintext.len() + TAG_LEN)?;
        let rekey = self.aead.nonce == MAX_NONCE;
        let mut wire = header.to_vec();
        wire.extend(self.aead.seal(plaintext, &header)?);
        if rekey {
            self.aead = SessionAead::new(&wire, &self.united_key, self.algorithm);
        }
        Ok(wire)
    }

    pub fn seal_records(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        for chunk in plaintext.chunks(MAX_WRITE_PLAINTEXT) {
            output.extend(self.seal_record(chunk)?);
        }
        Ok(output)
    }

    pub fn open_record(&mut self, wire: &[u8]) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(invalid("VLESS record cipher is poisoned"));
        }
        let result = self.open_record_inner(wire);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn open_record_inner(&mut self, wire: &[u8]) -> io::Result<Vec<u8>> {
        if wire.len() < 5 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let length = decode_record_header(&wire[..5])?;
        if wire.len() != 5 + length {
            return Err(invalid("truncated or trailing VLESS record bytes"));
        }
        let rekey = self.aead.nonce == MAX_NONCE;
        let plaintext = self.aead.open(&wire[5..], &wire[..5])?;
        if rekey {
            self.aead = SessionAead::new(wire, &self.united_key, self.algorithm);
        }
        Ok(plaintext)
    }
}

/// Buffers at most one bounded encrypted record; plaintext is released only
/// after that record authenticates. A failed call poisons the decoder.
pub struct RecordDecoder {
    cipher: RecordCipher,
    pending: Vec<u8>,
    needed: usize,
    failed: bool,
}

impl RecordDecoder {
    pub fn new(cipher: RecordCipher) -> Self {
        Self {
            cipher,
            pending: Vec::new(),
            needed: 5,
            failed: false,
        }
    }

    pub fn push(&mut self, mut input: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        if self.failed {
            return Err(invalid("VLESS record decoder is poisoned"));
        }
        let result = (|| {
            let mut plaintext = Vec::new();
            while !input.is_empty() {
                let take = input.len().min(self.needed - self.pending.len());
                self.pending.extend_from_slice(&input[..take]);
                input = &input[take..];
                if self.pending.len() < self.needed {
                    continue;
                }
                if self.needed == 5 {
                    self.needed += decode_record_header(&self.pending)?;
                } else {
                    plaintext.push(self.cipher.open_record(&self.pending)?);
                    self.pending.clear();
                    self.needed = 5;
                }
            }
            Ok(plaintext)
        })();
        if result.is_err() {
            self.failed = true;
            self.pending.clear();
        }
        result
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(invalid("VLESS record decoder is poisoned"));
        }
        if !self.pending.is_empty() {
            self.failed = true;
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

struct Ctr {
    cipher: Aes256,
    initial_counter: [u8; 16],
    counter: [u8; 16],
    stream: [u8; 16],
    position: usize,
    exhausted: bool,
}

impl Ctr {
    fn new(key: &[u8], iv: [u8; 16]) -> Self {
        let key = Zeroizing::new(derive_key(b"VLESS", key));
        Self {
            cipher: Aes256::new((&*key).into()),
            initial_counter: iv,
            counter: iv,
            stream: [0; 16],
            position: 16,
            exhausted: false,
        }
    }

    fn apply(&mut self, data: &mut [u8]) -> io::Result<()> {
        for byte in data {
            if self.position == 16 {
                if self.exhausted {
                    return Err(invalid("VLESS header CTR counter exhausted"));
                }
                let mut block = self.counter.into();
                self.cipher.encrypt_block(&mut block);
                self.stream.copy_from_slice(&block);
                self.position = 0;
                for counter_byte in self.counter.iter_mut().rev() {
                    *counter_byte = counter_byte.wrapping_add(1);
                    if *counter_byte != 0 {
                        break;
                    }
                }
                self.exhausted = self.counter == self.initial_counter;
            }
            *byte ^= self.stream[self.position];
            self.position += 1;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskDirection {
    Encode,
    Decode,
}

/// Pinned XorConn behavior: AES-256-CTR transforms record headers only. Payload
/// bytes and the initial `skip` handshake bytes do not consume keystream.
/// A malformed header poisons this state; discard the connection and data.
pub struct HeaderMask {
    ctr: Ctr,
    direction: MaskDirection,
    skip: usize,
    header: [u8; 5],
    header_len: usize,
    failed: bool,
}

impl HeaderMask {
    pub fn new(key: &[u8], iv: [u8; 16], skip: usize, direction: MaskDirection) -> Self {
        Self {
            ctr: Ctr::new(key, iv),
            direction,
            skip,
            header: [0; 5],
            header_len: 0,
            failed: false,
        }
    }

    pub fn apply(&mut self, input: &mut [u8]) -> io::Result<()> {
        if self.failed {
            return Err(invalid("VLESS header mask is poisoned"));
        }
        let result = (|| {
            let mut input = input;
            while !input.is_empty() {
                let skip = self.skip.min(input.len());
                self.skip -= skip;
                input = &mut input[skip..];
                if input.is_empty() {
                    break;
                }
                let take = (5 - self.header_len).min(input.len());
                let (part, remaining) = input.split_at_mut(take);
                if self.direction == MaskDirection::Decode {
                    self.ctr.apply(part)?;
                }
                self.header[self.header_len..self.header_len + take].copy_from_slice(part);
                if self.direction == MaskDirection::Encode {
                    self.ctr.apply(part)?;
                }
                self.header_len += take;
                if self.header_len == 5 {
                    self.skip = decode_record_header(&self.header)?;
                    self.header_len = 0;
                }
                input = remaining;
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(invalid("VLESS header mask is poisoned"));
        }
        if self.skip != 0 || self.header_len != 0 {
            self.failed = true;
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn independent_python_aead_record_vectors() {
        // Python blake3 1.0.9 plus cryptography 50.0.1 AESGCM/ChaCha20Poly1305.
        assert_eq!(
            hex(&derive_key(b"context", b"united-key")),
            "97fc931ee2de3eec870156eb6c218fda76075318942daf7143bcd7a32549cd75"
        );
        for (algorithm, expected) in [
            (
                Algorithm::Aes256Gcm,
                "170303001526aa1657be9011f10b92eec781d37d3559a7c5719c",
            ),
            (
                Algorithm::ChaCha20Poly1305,
                "1703030015233fbf61ac60c709657acddcbcb80b15d00d11978c",
            ),
        ] {
            let wire = RecordCipher::new(b"context", b"united-key", algorithm)
                .seal_record(b"hello")
                .unwrap();
            assert_eq!(hex(&wire), expected);
        }
    }

    #[test]
    fn nonce_preincrement_and_record_boundaries() {
        for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
            let mut seal = RecordCipher::new(b"context", b"united-key", algorithm);
            let mut open = RecordCipher::new(b"context", b"united-key", algorithm);
            let first = seal.seal_record(b"hello").unwrap();
            assert_eq!(&first[..5], &[23, 3, 3, 0, 21]);
            assert_eq!(seal.aead.nonce(), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            assert_eq!(open.open_record(&first).unwrap(), b"hello");
            let second = seal.seal_record(b"hello").unwrap();
            assert_ne!(first, second);
            assert_eq!(open.open_record(&second).unwrap(), b"hello");
            assert!(seal.seal_record(&[]).is_err());
            assert!(seal.seal_record(&vec![0; 8193]).is_err());
        }
    }

    #[test]
    fn record_authentication_covers_headers_content_and_tags() {
        for algorithm in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
            let wire = RecordCipher::new(b"ctx", b"key", algorithm)
                .seal_record(b"secret")
                .unwrap();
            for index in 0..wire.len() {
                let mut corrupt = wire.clone();
                corrupt[index] ^= 1;
                let mut receiver = RecordCipher::new(b"ctx", b"key", algorithm);
                assert!(receiver.open_record(&corrupt).is_err());
                assert!(receiver.open_record(&wire).is_err());
            }
            for length in 0..wire.len() {
                assert!(
                    RecordCipher::new(b"ctx", b"key", algorithm)
                        .open_record(&wire[..length])
                        .is_err()
                );
            }
            assert!(
                RecordCipher::new(b"wrong", b"key", algorithm)
                    .open_record(&wire)
                    .is_err()
            );
        }
    }

    #[test]
    fn explicit_nonce_authentication_failure_is_terminal() {
        let sender = SessionAead::new(b"ctx", b"key", Algorithm::Aes256Gcm);
        let wire = sender.seal_at(&MAX_NONCE, b"handshake", &[]).unwrap();
        let mut receiver = SessionAead::new(b"ctx", b"key", Algorithm::Aes256Gcm);
        let mut corrupt = wire.clone();
        corrupt[0] ^= 1;
        assert!(receiver.open_at(&MAX_NONCE, &corrupt, &[]).is_err());
        assert!(receiver.open_at(&MAX_NONCE, &wire, &[]).is_err());
        assert!(receiver.seal_at(&[1; 12], b"later", &[]).is_err());
    }

    #[test]
    fn wrap_record_uses_zero_nonce_then_rekeys_from_entire_wire_record() {
        let mut seal = RecordCipher::new(b"ctx", b"key", Algorithm::Aes256Gcm);
        let mut open = RecordCipher::new(b"ctx", b"key", Algorithm::Aes256Gcm);
        seal.aead.nonce = MAX_NONCE;
        open.aead.nonce = MAX_NONCE;
        let wire = seal.seal_record(b"wrap").unwrap();
        let before = SessionAead::new(b"ctx", b"key", Algorithm::Aes256Gcm);
        assert_eq!(
            &wire[5..],
            before.seal_at(&[0; 12], b"wrap", &wire[..5]).unwrap()
        );
        assert_eq!(open.open_record(&wire).unwrap(), b"wrap");
        let next = seal.seal_record(b"after").unwrap();
        let mut expected = RecordCipher::new(&wire, b"key", Algorithm::Aes256Gcm);
        assert_eq!(next, expected.seal_record(b"after").unwrap());
        assert_eq!(open.open_record(&next).unwrap(), b"after");
    }

    #[test]
    fn incremental_records_and_truncated_eof() {
        let plaintext = vec![7; 20_000];
        let wire = RecordCipher::new(b"ctx", b"key", Algorithm::ChaCha20Poly1305)
            .seal_records(&plaintext)
            .unwrap();
        let mut receiver = RecordDecoder::new(RecordCipher::new(
            b"ctx",
            b"key",
            Algorithm::ChaCha20Poly1305,
        ));
        let mut actual = Vec::new();
        for chunk in wire.chunks(3) {
            for block in receiver.push(chunk).unwrap() {
                actual.extend(block);
            }
        }
        receiver.finish().unwrap();
        assert_eq!(actual, plaintext);
        let mut receiver = RecordDecoder::new(RecordCipher::new(
            b"ctx",
            b"key",
            Algorithm::ChaCha20Poly1305,
        ));
        receiver.push(&wire[..4]).unwrap();
        assert!(receiver.finish().is_err());
    }

    #[test]
    fn header_mask_preserves_body_and_handles_every_split() {
        let mut records = RecordCipher::new(b"ctx", b"key", Algorithm::Aes256Gcm);
        let first = records.seal_record(b"abc").unwrap();
        let second = records.seal_record(b"defg").unwrap();
        let original = [b"prefix".as_slice(), &first, &second].concat();
        let mut expected = original.clone();
        HeaderMask::new(b"key", [9; 16], 6, MaskDirection::Encode)
            .apply(&mut expected)
            .unwrap();
        assert_eq!(&expected[..6], b"prefix");
        assert_eq!(&expected[11..6 + first.len()], &first[5..]);
        // Independent Python AES-CTR vector: only the ten header bytes advance CTR.
        assert_eq!(hex(&expected[6..11]), "cde63eccb8");
        assert_eq!(
            hex(&expected[6 + first.len()..11 + first.len()]),
            "25f39b2ed4"
        );
        for split in 0..=original.len() {
            let mut masked = original.clone();
            let mut encode = HeaderMask::new(b"key", [9; 16], 6, MaskDirection::Encode);
            encode.apply(&mut masked[..split]).unwrap();
            encode.apply(&mut masked[split..]).unwrap();
            encode.finish().unwrap();
            assert_eq!(masked, expected);
            let mut decode = HeaderMask::new(b"key", [9; 16], 6, MaskDirection::Decode);
            for part in masked.chunks_mut(2) {
                decode.apply(part).unwrap();
            }
            decode.finish().unwrap();
            assert_eq!(masked, original);
        }
    }

    #[test]
    fn header_ctr_numeric_wrap_does_not_reuse_initial_counter() {
        let mut original = Vec::new();
        for value in 0..4 {
            original.extend([23, 3, 3, 0, 17]);
            original.extend([value; 17]);
        }
        let mut masked = original.clone();
        let mut sender = HeaderMask::new(b"key", [255; 16], 0, MaskDirection::Encode);
        // Split just after the first byte of the fourth header, the end of AES(max).
        sender.apply(&mut masked[..67]).unwrap();
        sender.apply(&mut masked[67..]).unwrap();
        sender.finish().unwrap();
        let headers: Vec<u8> = masked
            .chunks_exact(22)
            .flat_map(|record| record[..5].iter().copied())
            .collect();
        // Independent Python AES-CTR (max IV, then modulo wrap to zero).
        assert_eq!(hex(&headers), "c4310c98c7afb6dbc8f1a31ac6768aec11ce07b5");
        let mut receiver = HeaderMask::new(b"key", [255; 16], 0, MaskDirection::Decode);
        for chunk in masked.chunks_mut(3) {
            receiver.apply(chunk).unwrap();
        }
        receiver.finish().unwrap();
        assert_eq!(masked, original);
    }
}
