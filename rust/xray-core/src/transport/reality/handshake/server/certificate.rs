use std::io;

use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use super::super::super::RealityAuthKey;
use super::super::wire;
use super::invalid;

fn vector24(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() > 0xff_ffff {
        return Err(invalid("TLS certificate vector exceeds 24-bit length"));
    }
    let mut out = (bytes.len() as u32).to_be_bytes()[1..].to_vec();
    out.extend_from_slice(bytes);
    Ok(out)
}

pub(super) fn create(
    server_name: &str,
    auth: &RealityAuthKey,
) -> io::Result<(Vec<u8>, SigningKey)> {
    let mut seed = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(io::Error::other)?;
    let signer = SigningKey::from_bytes(&seed);
    // RFC8410 OneAsymmetricKey: Ed25519 OID and nested OCTET STRING seed.
    let mut pkcs8 = Zeroizing::new(vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(seed.as_ref());
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        &rcgen::PKCS_ED25519,
    )
    .map_err(io::Error::other)?;
    let mut der = rcgen::CertificateParams::new(vec![server_name.to_owned()])
        .map_err(io::Error::other)?
        .self_signed(&key)
        .map_err(io::Error::other)?
        .der()
        .to_vec();
    // Parse/check the generated DER before replacing its final signature bytes;
    // the Ed25519 algorithm and SPKI remain unchanged, exactly as REALITY does.
    let (remaining, cert) = X509Certificate::from_der(&der)
        .map_err(|_| invalid("failed to parse generated REALITY certificate"))?;
    if !remaining.is_empty()
        || cert.signature_value.unused_bits != 0
        || cert.signature_value.data.len() != 64
        || der.len() < 64
        || der[der.len() - 64..] != *cert.signature_value.data.as_ref()
        || cert.public_key().subject_public_key.data.as_ref() != signer.verifying_key().as_bytes()
    {
        return Err(invalid("unexpected Ed25519 certificate representation"));
    }
    let marker = auth.certificate_marker(signer.verifying_key().as_bytes());
    let end = der.len();
    der[end - 64..].copy_from_slice(&marker);
    let mut entry = vector24(&der)?;
    entry.extend_from_slice(&[0, 0]);
    let mut body = vec![0];
    body.extend(vector24(&entry)?);
    Ok((wire::handshake(11, &body)?, signer))
}
