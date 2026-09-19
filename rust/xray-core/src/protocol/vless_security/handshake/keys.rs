use std::io;

use ml_kem::{Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768};
use rand::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use super::invalid;

pub(super) const MLKEM_PUBLIC_LEN: usize = 1184;
pub(super) const MLKEM_CIPHERTEXT_LEN: usize = 1088;

pub(super) enum PublicKey {
    X25519([u8; 32]),
    MlKem(Box<EncapsulationKey<MlKem768>>),
}

pub(super) enum PrivateKey {
    X25519(Zeroizing<[u8; 32]>),
    MlKem(Box<DecapsulationKey<MlKem768>>),
}

pub(super) fn random_bytes<const N: usize>(
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    rng.try_fill_bytes(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

pub(super) fn parse_mlkem(bytes: &[u8]) -> io::Result<EncapsulationKey<MlKem768>> {
    let encoded = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(bytes)
        .map_err(|_| invalid("invalid ML-KEM-768 public key length"))?;
    EncapsulationKey::new(&encoded).map_err(|_| invalid("invalid ML-KEM-768 public key encoding"))
}

pub(super) fn encapsulate(
    key: &EncapsulationKey<MlKem768>,
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    // RustCrypto's 0.3 RNG trait differs from rand 0.8. Supply exactly 32 fresh
    // uniform CSPRNG bytes to the FIPS 203 encapsulation primitive instead.
    let entropy = Zeroizing::new(random_bytes::<32>(rng)?);
    let (ciphertext, shared) = key.encapsulate_deterministic(&(*entropy).into());
    Ok((ciphertext.to_vec(), Zeroizing::new(shared.into())))
}

pub(super) fn decapsulate(
    key: &DecapsulationKey<MlKem768>,
    ciphertext: &[u8],
) -> io::Result<Zeroizing<[u8; 32]>> {
    let ciphertext = ml_kem::Ciphertext::<MlKem768>::try_from(ciphertext)
        .map_err(|_| invalid("invalid ML-KEM-768 ciphertext length"))?;
    Ok(Zeroizing::new(key.decapsulate(&ciphertext).into()))
}

pub(super) fn ecdh(private: &[u8; 32], public: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
    let public = public
        .try_into()
        .map_err(|_| invalid("invalid X25519 public key length"))?;
    let shared = Zeroizing::new(x25519(*private, public));
    if bool::from(shared.as_ref().ct_eq(&[0; 32])) {
        return Err(invalid("low-order VLESS X25519 public key"));
    }
    Ok(shared)
}

impl PublicKey {
    pub(super) fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::X25519(key) => key.to_vec(),
            Self::MlKem(key) => key.to_bytes().to_vec(),
        }
    }

    pub(super) fn parse(bytes: &[u8]) -> io::Result<Self> {
        match bytes.len() {
            32 => Ok(Self::X25519(bytes.try_into().expect("checked key length"))),
            MLKEM_PUBLIC_LEN => Ok(Self::MlKem(Box::new(parse_mlkem(bytes)?))),
            _ => Err(invalid("VLESS server public key must be 32 or 1184 bytes")),
        }
    }

    pub(super) fn exchange(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> io::Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        match self {
            Self::X25519(public) => {
                let private = Zeroizing::new(random_bytes::<32>(rng)?);
                let share = x25519(*private, X25519_BASEPOINT_BYTES);
                Ok((share.to_vec(), ecdh(&private, public)?))
            }
            Self::MlKem(key) => encapsulate(key, rng),
        }
    }
}

impl PrivateKey {
    pub(super) fn parse(bytes: &[u8]) -> io::Result<Self> {
        match bytes.len() {
            32 => Ok(Self::X25519(Zeroizing::new(
                bytes.try_into().expect("checked key length"),
            ))),
            64 => {
                let seed: [u8; 64] = bytes.try_into().expect("checked seed length");
                let seed = Zeroizing::new(seed);
                Ok(Self::MlKem(Box::new(DecapsulationKey::from_seed(
                    (*seed).into(),
                ))))
            }
            _ => Err(invalid(
                "VLESS server private key must be 32-byte X25519 or 64-byte ML-KEM seed",
            )),
        }
    }

    pub(super) fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::X25519(key) => x25519(**key, X25519_BASEPOINT_BYTES).to_vec(),
            Self::MlKem(key) => key.encapsulation_key().to_bytes().to_vec(),
        }
    }

    pub(super) fn share_len(&self) -> usize {
        match self {
            Self::X25519(_) => 32,
            Self::MlKem(_) => MLKEM_CIPHERTEXT_LEN,
        }
    }

    pub(super) fn exchange(&self, share: &[u8]) -> io::Result<Zeroizing<[u8; 32]>> {
        match self {
            Self::X25519(key) => {
                if share.len() != 32 || share[31] > 127 {
                    return Err(invalid("noncanonical VLESS NFS X25519 public key"));
                }
                // RFC 7748 reduces u >= p modulo p. Such aliases produce the
                // same NFS key but different wire hashes, bypassing exact-hello
                // replay history. Native generated shares are always < p.
                let mut modulus = [0xff; 32];
                modulus[0] = 0xed;
                modulus[31] = 0x7f;
                if share.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less {
                    return Err(invalid("noncanonical VLESS NFS X25519 field element"));
                }
                ecdh(key, share)
            }
            Self::MlKem(key) => decapsulate(key, share),
        }
    }
}

pub(super) struct Ephemeral {
    mlkem: DecapsulationKey<MlKem768>,
    x25519: Zeroizing<[u8; 32]>,
}

impl Ephemeral {
    pub(super) fn generate(rng: &mut (impl RngCore + CryptoRng)) -> io::Result<Self> {
        let seed = Zeroizing::new(random_bytes::<64>(rng)?);
        Ok(Self {
            mlkem: DecapsulationKey::from_seed((*seed).into()),
            x25519: Zeroizing::new(random_bytes::<32>(rng)?),
        })
    }

    pub(super) fn public_bytes(&self) -> Vec<u8> {
        let mut result = self.mlkem.encapsulation_key().to_bytes().to_vec();
        result.extend_from_slice(&x25519(*self.x25519, X25519_BASEPOINT_BYTES));
        result
    }

    pub(super) fn shared(&self, server_share: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        if server_share.len() != MLKEM_CIPHERTEXT_LEN + 32 {
            return Err(invalid("invalid VLESS server hybrid share length"));
        }
        let mlkem = decapsulate(&self.mlkem, &server_share[..MLKEM_CIPHERTEXT_LEN])?;
        let x25519 = ecdh(&self.x25519, &server_share[MLKEM_CIPHERTEXT_LEN..])?;
        let mut result = Zeroizing::new(Vec::with_capacity(96));
        result.extend_from_slice(mlkem.as_ref());
        result.extend_from_slice(x25519.as_ref());
        Ok(result)
    }
}

pub(super) fn server_hybrid(
    client_share: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> io::Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if client_share.len() != MLKEM_PUBLIC_LEN + 32 {
        return Err(invalid("invalid VLESS client hybrid share length"));
    }
    let mlkem_key = parse_mlkem(&client_share[..MLKEM_PUBLIC_LEN])?;
    let (mut share, mlkem_secret) = encapsulate(&mlkem_key, rng)?;
    let x_private = Zeroizing::new(random_bytes::<32>(rng)?);
    let x_shared = ecdh(&x_private, &client_share[MLKEM_PUBLIC_LEN..])?;
    share.extend_from_slice(&x25519(*x_private, X25519_BASEPOINT_BYTES));
    let mut shared = Zeroizing::new(Vec::with_capacity(96));
    shared.extend_from_slice(mlkem_secret.as_ref());
    shared.extend_from_slice(x_shared.as_ref());
    Ok((share, shared))
}
