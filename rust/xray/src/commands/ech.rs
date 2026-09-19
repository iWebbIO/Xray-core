use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use super::EchArgs;

/// ECHConfig draft version 0xfe0d, DHKEM(X25519, HKDF-SHA256), with the
/// same nine KDF/AEAD combinations and ordering as `tls/ech.go`.
fn generate(private: [u8; 32], server_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(
        server_name.len() <= 255,
        "ECH public name exceeds 255 bytes"
    );
    let public = PublicKey::from(&StaticSecret::from(private));
    let mut contents = vec![0]; // config ID
    contents.extend_from_slice(&0x0020_u16.to_be_bytes());
    contents.extend_from_slice(&32_u16.to_be_bytes());
    contents.extend_from_slice(public.as_bytes());
    contents.extend_from_slice(&36_u16.to_be_bytes());
    for kdf in 1_u16..=3 {
        for aead in 1_u16..=3 {
            contents.extend_from_slice(&kdf.to_be_bytes());
            contents.extend_from_slice(&aead.to_be_bytes());
        }
    }
    contents.push(0); // maximum name length
    contents.push(server_name.len() as u8);
    contents.extend_from_slice(server_name.as_bytes());
    contents.extend_from_slice(&0_u16.to_be_bytes()); // extensions
    let mut config = 0xfe0d_u16.to_be_bytes().to_vec();
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    let mut configs = (config.len() as u16).to_be_bytes().to_vec();
    configs.extend_from_slice(&config);
    let mut keys = 32_u16.to_be_bytes().to_vec();
    keys.extend_from_slice(&private);
    keys.extend_from_slice(&(config.len() as u16).to_be_bytes());
    keys.extend_from_slice(&config);
    Ok((configs, keys))
}

fn take_vector<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u16::from_be_bytes(input.get(..2)?.try_into().ok()?) as usize;
    let value = input.get(2..2 + length)?;
    *input = &input[2 + length..];
    Some(value)
}

/// Preserve the source command's list restoration: every key set contributes
/// its own length-prefixed config, including unknown ECH versions. Structural
/// decoding does not claim to validate keys for a TLS implementation.
fn restore(mut keys: &[u8]) -> Option<Vec<u8>> {
    let mut configs = Vec::new();
    while !keys.is_empty() {
        take_vector(&mut keys)?;
        let config = take_vector(&mut keys)?;
        configs.extend_from_slice(&(config.len() as u16).to_be_bytes());
        configs.extend_from_slice(config);
    }
    Some(configs)
}

fn format(configs: &[u8], keys: &[u8], pem: bool) -> String {
    if pem {
        super::pem("ECH CONFIGS", configs) + &super::pem("ECH KEYS", keys)
    } else {
        std::format!(
            "ECH config list: \n{}\nECH server keys: \n{}\n",
            STANDARD.encode(configs),
            STANDARD.encode(keys),
        )
    }
}

// Preserve Go's non-strict StdEncoding and its byte offsets on malformed
// padding/newlines. Rust base64 error categories do not contain equivalent
// offsets for every padding case, so this small decoder tracks source bytes.
fn decode_standard(input: &[u8]) -> std::result::Result<Vec<u8>, usize> {
    let mut output = Vec::with_capacity(input.len() / 4 * 3);
    let mut offset = 0;
    loop {
        let mut quantum = [0_u8; 4];
        let mut count = 0;
        let mut length = 4;
        while count < 4 {
            if offset == input.len() {
                return if count == 0 {
                    Ok(output)
                } else {
                    Err(offset - count)
                };
            }
            let byte = input[offset];
            offset += 1;
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'\r' | b'\n' => continue,
                b'=' => {
                    if count < 2 {
                        return Err(offset - 1);
                    }
                    if count == 2 {
                        while input
                            .get(offset)
                            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
                        {
                            offset += 1;
                        }
                        if offset == input.len() {
                            return Err(offset);
                        }
                        if input[offset] != b'=' {
                            return Err(offset - 1);
                        }
                        offset += 1;
                    }
                    while input
                        .get(offset)
                        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
                    {
                        offset += 1;
                    }
                    if offset < input.len() {
                        return Err(offset);
                    }
                    length = count;
                    break;
                }
                _ => return Err(offset - 1),
            };
            quantum[count] = value;
            count += 1;
        }
        output.push(quantum[0] << 2 | quantum[1] >> 4);
        if length >= 3 {
            output.push(quantum[1] << 4 | quantum[2] >> 2);
        }
        if length == 4 {
            output.push(quantum[2] << 6 | quantum[3]);
        }
    }
}

pub(super) fn run(args: &EchArgs) -> Result<String> {
    let (configs, keys) = if args.input.is_empty() {
        let mut private = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut private)?;
        generate(private, &args.server_name)?
    } else {
        let keys = match decode_standard(args.input.as_bytes()) {
            Ok(keys) => keys,
            Err(index) => {
                return Ok(std::format!(
                    "Failed to decode ECHServerKeys: illegal base64 data at input byte {index}\n"
                ));
            }
        };
        let Some(configs) = restore(&keys) else {
            return Ok("Failed to decode ECHServerKeys: goech: invalid length\n".into());
        };
        (configs, keys)
    };
    Ok(format(&configs, &keys, args.pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ech_matches_independent_go_restore_fixture() {
        let fixture = include_str!("fixtures/ech-sequence.txt");
        let (configs, keys) =
            generate(std::array::from_fn(|i| i as u8), "cloudflare-ech.com").unwrap();
        assert_eq!(format(&configs, &keys, false), fixture);
        let args = EchArgs {
            server_name: "ignored.test".into(),
            pem: false,
            input: STANDARD.encode(&keys),
        };
        assert_eq!(run(&args).unwrap(), fixture);
    }

    #[test]
    fn multiple_keysets_preserve_source_length_prefixes() {
        let (config, key) = generate([7; 32], "example.com").unwrap();
        let mut two_keys = key.clone();
        two_keys.extend_from_slice(&key);
        let mut two_configs = config.clone();
        two_configs.extend_from_slice(&config);
        assert_eq!(restore(&two_keys).unwrap(), two_configs);
    }

    #[test]
    fn malformed_key_lengths_are_rejected() {
        let (_, keys) = generate([9; 32], "example.com").unwrap();
        assert_eq!(restore(&[]), Some(Vec::new()));
        for end in 1..keys.len() {
            assert!(
                restore(&keys[..end]).is_none(),
                "accepted truncation at {end}"
            );
        }
        let mut extra = keys;
        extra.push(0);
        assert!(restore(&extra).is_none());
        assert_eq!(
            run(&EchArgs {
                server_name: String::new(),
                pem: false,
                input: "!".into()
            })
            .unwrap(),
            "Failed to decode ECHServerKeys: illegal base64 data at input byte 0\n"
        );
    }

    #[test]
    fn pem_labels_wrapping_and_trailing_newlines_match_go() {
        let (configs, keys) = generate([1; 32], "example.com").unwrap();
        let output = format(&configs, &keys, true);
        assert!(output.starts_with("-----BEGIN ECH CONFIGS-----\n"));
        assert!(output.ends_with("-----END ECH KEYS-----\n"));
        for line in output.lines().filter(|line| !line.starts_with("-----")) {
            assert!(line.len() <= 64);
        }
        assert!(generate([0; 32], &"a".repeat(256)).is_err());
    }

    #[test]
    fn base64_errors_match_go_offsets_and_noncanonical_bits() {
        for (input, index) in [
            ("!", 0),
            ("A", 0),
            ("AA", 0),
            ("AAA", 0),
            ("AAAAA", 4),
            ("AA=A", 2),
            ("A===", 1),
            ("AAAA====", 4),
            ("AA==!", 4),
            ("\n!", 1),
            ("AA\n=A", 3),
            ("AA==\n!", 5),
        ] {
            assert_eq!(decode_standard(input.as_bytes()), Err(index), "{input:?}");
        }
        assert_eq!(decode_standard(b"AB==\r\n"), Ok(vec![0]));
        for length in 0..150 {
            let input: Vec<_> = (0..length).map(|i| (i * 73) as u8).collect();
            let encoded = STANDARD.encode(&input);
            assert_eq!(decode_standard(encoded.as_bytes()).unwrap(), input);
        }
    }
}
