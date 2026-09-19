use anyhow::{Context, Result};
use base64::{
    Engine,
    alphabet::URL_SAFE,
    engine::{
        DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::URL_SAFE_NO_PAD,
    },
};
use ml_dsa::{KeyExport as _, Keypair as _, MlDsa65, SigningKey};
use ml_kem::{DecapsulationKey, MlKem768};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

/// Go's RawURLEncoding accepts nonzero trailing padding bits and CR/LF.
/// Its callers ignore DecodeString's error and keep already decoded quanta.
fn input_seed<const N: usize>(input: &str) -> Result<Option<[u8; N]>> {
    if input.is_empty() {
        let mut seed = [0; N];
        rand::rngs::OsRng
            .try_fill_bytes(&mut seed)
            .context("operating system randomness failed")?;
        return Ok(Some(seed));
    }
    let engine = GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    let mut decoded = Vec::new();
    for quantum in clean.chunks(4) {
        match engine.decode(quantum) {
            Ok(bytes) => decoded.extend_from_slice(&bytes),
            Err(_) => break,
        }
        if decoded.len() > N {
            return Ok(None);
        }
    }
    Ok(decoded.try_into().ok())
}

fn mlkem_public(seed: [u8; 64]) -> Vec<u8> {
    let key = DecapsulationKey::<MlKem768>::from_seed(seed.into());
    key.encapsulation_key().to_bytes().to_vec()
}

pub(super) fn mlkem768(input: &str) -> Result<String> {
    let Some(seed) = input_seed::<64>(input)? else {
        return Ok("Invalid length ML-KEM-768 seed.\n".into());
    };
    let client = mlkem_public(seed);
    Ok(format!(
        "Seed: {}\nClient: {}\nHash32: {}\n",
        URL_SAFE_NO_PAD.encode(seed),
        URL_SAFE_NO_PAD.encode(&client),
        URL_SAFE_NO_PAD.encode(blake3::hash(&client).as_bytes()),
    ))
}

pub(super) fn mldsa65(input: &str) -> Result<String> {
    let Some(seed) = input_seed::<32>(input)? else {
        return Ok("Invalid length ML-DSA-65 seed.\n".into());
    };
    let key = SigningKey::<MlDsa65>::from_seed(&seed.into());
    Ok(format!(
        "Seed: {}\nVerify: {}\n",
        URL_SAFE_NO_PAD.encode(seed),
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    ))
}

fn vlessenc_from_seeds(mut x25519: [u8; 32], mlkem: [u8; 64]) -> String {
    x25519[0] &= 248;
    x25519[31] &= 127;
    x25519[31] |= 64;
    let password = PublicKey::from(&StaticSecret::from(x25519));
    format!(
        concat!(
            "Choose one Authentication to use, do not mix them. Ephemeral key exchange is Post-Quantum safe anyway.\n\n",
            "Authentication: X25519, not Post-Quantum\n",
            "\"decryption\": \"mlkem768x25519plus.native.600s.{}\"\n",
            "\"encryption\": \"mlkem768x25519plus.native.0rtt.{}\"\n\n",
            "Authentication: ML-KEM-768, Post-Quantum\n",
            "\"decryption\": \"mlkem768x25519plus.native.600s.{}\"\n",
            "\"encryption\": \"mlkem768x25519plus.native.0rtt.{}\"\n",
        ),
        URL_SAFE_NO_PAD.encode(x25519),
        URL_SAFE_NO_PAD.encode(password.as_bytes()),
        URL_SAFE_NO_PAD.encode(mlkem),
        URL_SAFE_NO_PAD.encode(mlkem_public(mlkem)),
    )
}

pub(super) fn vlessenc() -> Result<String> {
    Ok(vlessenc_from_seeds(
        input_seed::<32>("")?.expect("generated a fixed-size seed"),
        input_seed::<64>("")?.expect("generated a fixed-size seed"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_matches_go_seed_fixtures_byte_for_byte() {
        for (seed, fixture) in [
            ([0_u8; 64], include_str!("fixtures/mlkem768-zero.txt")),
            (
                std::array::from_fn(|i| i as u8),
                include_str!("fixtures/mlkem768-sequence.txt"),
            ),
        ] {
            assert_eq!(mlkem768(&URL_SAFE_NO_PAD.encode(seed)).unwrap(), fixture);
        }
    }

    #[test]
    fn mldsa_matches_go_seed_fixtures_byte_for_byte() {
        for (seed, fixture) in [
            ([0_u8; 32], include_str!("fixtures/mldsa65-zero.txt")),
            (
                std::array::from_fn(|i| i as u8),
                include_str!("fixtures/mldsa65-sequence.txt"),
            ),
        ] {
            assert_eq!(mldsa65(&URL_SAFE_NO_PAD.encode(seed)).unwrap(), fixture);
        }
    }

    #[test]
    fn invalid_seed_outputs_match_go() {
        for input in ["!", "A", "AA", "not a seed", "AAAA=", "////"] {
            assert_eq!(
                mlkem768(input).unwrap(),
                "Invalid length ML-KEM-768 seed.\n"
            );
            assert_eq!(mldsa65(input).unwrap(), "Invalid length ML-DSA-65 seed.\n");
        }
        assert_eq!(
            input_seed::<32>(&URL_SAFE_NO_PAD.encode([0; 31])).unwrap(),
            None
        );
        assert_eq!(
            input_seed::<32>(&URL_SAFE_NO_PAD.encode([0; 33])).unwrap(),
            None
        );
    }

    #[test]
    fn go_raw_base64_accepts_crlf_and_unused_bits() {
        let mut encoded = URL_SAFE_NO_PAD.encode([0; 32]);
        encoded.insert_str(8, "\r\n");
        encoded.pop();
        encoded.push('B');
        assert_eq!(input_seed::<32>(&encoded).unwrap(), Some([0; 32]));
    }

    #[test]
    fn vless_output_has_four_compatible_config_strings() {
        let output = vlessenc_from_seeds([0; 32], [0; 64]);
        let fields: Vec<_> = output
            .lines()
            .filter(|line| line.starts_with('"'))
            .collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(
            fields[0],
            "\"decryption\": \"mlkem768x25519plus.native.600s.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA\""
        );
        assert_eq!(
            fields[1],
            "\"encryption\": \"mlkem768x25519plus.native.0rtt.L-V9o0fNYkMVKNqsX7spBzD_9oSvxM_C7ZCZX1jLO3Q\""
        );
        assert!(fields[2].contains(&URL_SAFE_NO_PAD.encode([0; 64])));
        let expected_client = include_str!("fixtures/mlkem768-zero.txt")
            .lines()
            .nth(1)
            .unwrap()
            .strip_prefix("Client: ")
            .unwrap();
        assert!(fields[3].contains(expected_client));
        assert!(output.ends_with("\"\n"));
    }
}
