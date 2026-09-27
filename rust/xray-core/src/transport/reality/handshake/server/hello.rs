use std::{collections::BTreeSet, io};

use ml_kem::{EncapsulationKey, MlKem768};
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use super::super::wire::{self, Cursor};
use super::{CipherSuite, KeyExchangeGroup, ServerConfig, invalid};

pub(super) struct Offer<'a> {
    pub(super) session_id: &'a [u8],
    pub(super) server_name: &'a [u8],
    suites: Vec<u16>,
    groups: Vec<u16>,
    shares: Vec<(u16, &'a [u8])>,
    alpn: Vec<&'a [u8]>,
}

pub(super) struct Selected<'a> {
    pub(super) suite: CipherSuite,
    pub(super) group: KeyExchangeGroup,
    pub(super) share: &'a [u8],
    pub(super) alpn: Option<Vec<u8>>,
}

fn u16_list(bytes: &[u8]) -> io::Result<Vec<u16>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(invalid("invalid TLS u16 list"));
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .collect())
}

impl<'a> Offer<'a> {
    pub(super) fn parse(message: &'a [u8]) -> io::Result<Self> {
        let mut outer = Cursor::new(message);
        if outer.u8()? != 1 {
            return Err(invalid("expected TLS ClientHello"));
        }
        let mut input = Cursor::new(outer.vec24()?);
        outer.done()?;
        if input.u16()? != 0x0303 {
            return Err(invalid("ClientHello legacy version must be TLS 1.2"));
        }
        input.take(32)?;
        let session_id = input.vec8()?;
        if session_id.len() != 32 {
            return Err(invalid("REALITY requires a 32-byte session ID"));
        }
        let suites = u16_list(input.vec16()?)?;
        if input.vec8()? != [0] {
            return Err(invalid("TLS 1.3 requires null compression"));
        }
        let mut extensions = Cursor::new(input.vec16()?);
        input.done()?;
        let mut result = Self {
            session_id,
            server_name: &[],
            suites,
            groups: vec![],
            shares: vec![],
            alpn: vec![],
        };
        let mut seen = BTreeSet::new();
        let mut tls13 = false;
        while !extensions.rest.is_empty() {
            let id = extensions.u16()?;
            let value = extensions.vec16()?;
            if !seen.insert(id) {
                return Err(invalid("duplicate ClientHello extension"));
            }
            let mut field = Cursor::new(value);
            match id {
                0 => {
                    let mut names = Cursor::new(field.vec16()?);
                    let mut kinds = BTreeSet::new();
                    while !names.rest.is_empty() {
                        let kind = names.u8()?;
                        let name = names.vec16()?;
                        if name.is_empty() || !kinds.insert(kind) {
                            return Err(invalid("invalid TLS SNI list"));
                        }
                        if kind == 0 {
                            result.server_name = name;
                        }
                    }
                }
                10 => result.groups = u16_list(field.vec16()?)?,
                16 => {
                    let mut protocols = Cursor::new(field.vec16()?);
                    if protocols.rest.is_empty() {
                        return Err(invalid("empty ALPN offer"));
                    }
                    while !protocols.rest.is_empty() {
                        let protocol = protocols.vec8()?;
                        if protocol.is_empty() {
                            return Err(invalid("empty ALPN protocol"));
                        }
                        result.alpn.push(protocol);
                    }
                }
                43 => tls13 = u16_list(field.vec8()?)?.contains(&0x0304),
                51 => {
                    let mut shares = Cursor::new(field.vec16()?);
                    let mut groups = BTreeSet::new();
                    while !shares.rest.is_empty() {
                        let group = shares.u16()?;
                        let key = shares.vec16()?;
                        if key.is_empty() || !groups.insert(group) {
                            return Err(invalid("invalid or duplicate TLS key share"));
                        }
                        result.shares.push((group, key));
                    }
                }
                // Accepting a PSK without verifying its binder would bypass
                // the fresh-handshake transcript. This server never resumes.
                41 | 42 => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "REALITY server does not support PSK or early data",
                    ));
                }
                _ => {
                    field.take(value.len())?;
                }
            }
            field.done()?;
        }
        // The pinned Go REALITY server forces Ed25519 for its synthesized
        // certificate and never consults the client's signature_algorithms
        // list, so browser fingerprints without 0x0807 must stay acceptable.
        if !tls13 || result.server_name.is_empty() || result.groups.is_empty() {
            return Err(invalid("ClientHello lacks TLS 1.3, SNI or groups support"));
        }
        // Every offered key share, including unknown/GREASE groups, must also
        // appear in supported_groups. Unknown extensions/groups are not selected.
        if result
            .shares
            .iter()
            .any(|(group, _)| !result.groups.contains(group))
        {
            return Err(invalid(
                "ClientHello key share is absent from supported groups",
            ));
        }
        Ok(result)
    }

    pub(super) fn select(&self, config: &ServerConfig) -> io::Result<Selected<'a>> {
        let suite = config
            .cipher_suites
            .iter()
            .copied()
            .find(|s| self.suites.contains(&s.id()))
            .ok_or_else(|| invalid("no common TLS 1.3 cipher suite"))?;
        let (group, share) = config
            .key_exchange_groups
            .iter()
            .find_map(|group| {
                self.shares
                    .iter()
                    .find(|(id, _)| *id == group.id())
                    .map(|(_, key)| (*group, *key))
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no supported key share; HelloRetryRequest is not implemented",
                )
            })?;
        let expected = if group == KeyExchangeGroup::X25519MlKem768 {
            1216
        } else {
            32
        };
        if share.len() != expected {
            return Err(invalid("invalid negotiated client key share length"));
        }
        let alpn = config
            .alpn
            .iter()
            .find(|protocol| self.alpn.contains(&protocol.as_slice()))
            .cloned();
        if !config.alpn.is_empty() && !self.alpn.is_empty() && alpn.is_none() {
            return Err(invalid("no common ALPN protocol"));
        }
        Ok(Selected {
            suite,
            group,
            share,
            alpn,
        })
    }

    pub(super) fn select_target(
        &self,
        config: &ServerConfig,
        suite: CipherSuite,
        group: KeyExchangeGroup,
    ) -> io::Result<Selected<'a>> {
        if !config.cipher_suites.contains(&suite)
            || !self.suites.contains(&suite.id())
            || !config.key_exchange_groups.contains(&group)
        {
            return Err(invalid(
                "target selected a disallowed or unoffered TLS suite/group",
            ));
        }
        let share = self
            .shares
            .iter()
            .find(|(id, _)| *id == group.id())
            .map(|(_, share)| *share)
            .ok_or_else(|| invalid("target selected an unoffered TLS key share"))?;
        let expected = if group == KeyExchangeGroup::X25519MlKem768 {
            1216
        } else {
            32
        };
        if share.len() != expected {
            return Err(invalid("invalid target-selected client key share length"));
        }
        Ok(Selected {
            suite,
            group,
            share,
            alpn: None,
        })
    }
}

pub(super) fn exchange(
    group: KeyExchangeGroup,
    share: &[u8],
) -> io::Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let peer = match (group, share.len()) {
        (KeyExchangeGroup::X25519MlKem768, 1216) => &share[1184..],
        (KeyExchangeGroup::X25519, 32) => share,
        _ => return Err(invalid("invalid client key share")),
    };
    let mut private = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(private.as_mut())
        .map_err(io::Error::other)?;
    let peer: [u8; 32] = peer.try_into().unwrap();
    let ecdh = Zeroizing::new(x25519(*private, peer));
    if bool::from(ecdh.as_ref().ct_eq(&[0; 32])) {
        return Err(invalid("low-order X25519 client key share"));
    }
    let public = x25519(*private, X25519_BASEPOINT_BYTES);
    let mut response = Vec::new();
    let mut secret = Zeroizing::new(Vec::with_capacity(64));
    if group == KeyExchangeGroup::X25519MlKem768 {
        let encoded = ml_kem::kem::Key::<EncapsulationKey<MlKem768>>::try_from(&share[..1184])
            .map_err(|_| invalid("invalid ML-KEM encapsulation key length"))?;
        let key = EncapsulationKey::<MlKem768>::new(&encoded)
            .map_err(|_| invalid("invalid ML-KEM encapsulation key"))?;
        let mut randomness = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(randomness.as_mut())
            .map_err(io::Error::other)?;
        // A fresh uniform OS-random seed is required by encapsulate_deterministic.
        let (ciphertext, kem_secret) = key.encapsulate_deterministic(&(*randomness).into());
        let kem_secret = Zeroizing::new(kem_secret);
        response.extend_from_slice(ciphertext.as_slice());
        secret.extend_from_slice(kem_secret.as_slice());
    }
    response.extend_from_slice(&public);
    secret.extend_from_slice(ecdh.as_ref());
    Ok((response, secret))
}

pub(super) fn server_hello(
    session: &[u8],
    random: &[u8; 32],
    suite: CipherSuite,
    group: KeyExchangeGroup,
    share: &[u8],
) -> io::Result<Vec<u8>> {
    if session.len() != 32 {
        return Err(invalid("invalid server session-ID echo"));
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(session);
    body.extend_from_slice(&suite.id().to_be_bytes());
    body.push(0);
    let mut extensions = Vec::new();
    wire::extension(&mut extensions, 43, &[3, 4])?;
    let mut key = group.id().to_be_bytes().to_vec();
    key.extend(wire::vector16(share)?);
    wire::extension(&mut extensions, 51, &key)?;
    body.extend(wire::vector16(&extensions)?);
    wire::handshake(2, &body)
}

pub(super) fn encrypted_extensions(alpn: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let mut extensions = Vec::new();
    wire::extension(&mut extensions, 0, &[])?;
    if let Some(protocol) = alpn {
        let mut list = vec![protocol.len() as u8];
        list.extend_from_slice(protocol);
        wire::extension(&mut extensions, 16, &wire::vector16(&list)?)?;
    }
    wire::handshake(8, &wire::vector16(&extensions)?)
}
