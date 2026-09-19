use std::{fs, io::Write, path::Path};

use anyhow::{Context, Result, anyhow, bail, ensure};
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
    string::PrintableString,
};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

use super::CertArgs;

/// Parse Go `time.ParseDuration` syntax (including fractions, signed values,
/// microsecond spellings and the full signed 64-bit nanosecond range).
fn duration(input: &str) -> Result<time::Duration> {
    let original = input;
    let (negative, mut input) = match input.as_bytes().first() {
        Some(b'-') => (true, &input[1..]),
        Some(b'+') => (false, &input[1..]),
        _ => (false, input),
    };
    if input == "0" {
        return Ok(time::Duration::ZERO);
    }
    ensure!(!input.is_empty(), "invalid duration {original:?}");
    let mut total = 0_i128;
    while !input.is_empty() {
        let integer_end = input.bytes().take_while(u8::is_ascii_digit).count();
        let integer = &input[..integer_end];
        input = &input[integer_end..];
        let mut fraction = "";
        if let Some(rest) = input.strip_prefix('.') {
            let fraction_end = rest.bytes().take_while(u8::is_ascii_digit).count();
            fraction = &rest[..fraction_end];
            input = &rest[fraction_end..];
        }
        ensure!(
            !integer.is_empty() || !fraction.is_empty(),
            "invalid duration {original:?}"
        );
        let unit_end = input
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(input.len());
        let multiplier: i128 = match &input[..unit_end] {
            "ns" => 1,
            "us" | "Âµs" | "Î¼s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            unit => bail!("unknown or missing unit {unit:?} in duration {original:?}"),
        };
        input = &input[unit_end..];
        let whole = if integer.is_empty() {
            0
        } else {
            integer
                .parse::<i128>()
                .context("duration integer overflow")?
        };
        total = total
            .checked_add(whole.checked_mul(multiplier).context("duration overflow")?)
            .context("duration overflow")?;
        // Match Go's leadingFraction and float conversion, including the
        // rounding boundary for long fractions of an hour.
        let mut mantissa = 0_u64;
        let mut scale = 1_f64;
        for digit in fraction.bytes() {
            if mantissa > i64::MAX as u64 / 10 {
                break;
            }
            let next = mantissa * 10 + u64::from(digit - b'0');
            if next > (1_u64 << 63) {
                break;
            }
            mantissa = next;
            scale *= 10.;
        }
        if mantissa > 0 {
            total = total
                .checked_add((mantissa as f64 * (multiplier as f64 / scale)) as i128)
                .context("duration overflow")?;
        }
        ensure!(
            total <= i64::MAX as i128 + i128::from(negative),
            "duration overflow"
        );
    }
    let nanos = if negative { -total } else { total };
    Ok(time::Duration::nanoseconds(i64::try_from(nanos)?))
}

fn name_value(value: &str) -> DnValue {
    match PrintableString::try_from(value) {
        Ok(value) => DnValue::PrintableString(value),
        Err(_) => DnValue::Utf8String(value.to_owned()),
    }
}

fn create(args: &CertArgs, now: OffsetDateTime) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut serial = [0_u8; 16];
    rand::rngs::OsRng.try_fill_bytes(&mut serial)?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::OrganizationName, name_value(&args.org));
    if !args.name.is_empty() {
        distinguished_name.push(DnType::CommonName, name_value(&args.name));
    }
    let subject_alt_names = args
        .domain
        .iter()
        .map(|name| {
            ensure!(!name.is_empty(), "empty value");
            // Go always adds -domain to DNSNames, even when it looks like an IP.
            Ok(SanType::DnsName(name.clone().try_into()?))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.subject_alt_names = subject_alt_names;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now
        .checked_add(duration(&args.expire)?)
        .context("certificate expiration overflow")?;
    params.is_ca = if args.ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::ExplicitNoCa
    };
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    if args.ca {
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    }
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params
        .self_signed(&key)
        .context("failed to generate TLS certificate")?;
    Ok((cert.der().to_vec(), key.serialize_der()))
}

pub(super) fn generate(args: &CertArgs, out: &mut impl Write) -> Result<()> {
    let (certificate, key) = create(args, OffsetDateTime::now_utc())?;
    let certificate = super::pem("CERTIFICATE", &certificate);
    let key = super::pem("RSA PRIVATE KEY", &key);
    if args.json {
        let json = serde_json::json!({
            "certificate": certificate.lines().collect::<Vec<_>>(),
            "key": key.lines().collect::<Vec<_>>(),
        });
        serde_json::to_writer_pretty(&mut *out, &json)?;
        writeln!(out)?;
    }
    if !args.file.is_empty() {
        fs::write(format!("{}.crt", args.file), certificate)
            .context("failed to save certificate file")?;
        fs::write(format!("{}.key", args.file), key).context("failed to save private key file")?;
    }
    Ok(())
}

pub(super) struct CertificateInfo {
    pub raw: Vec<u8>,
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
}

impl CertificateInfo {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let (remaining, cert) = parse_x509_certificate(raw).map_err(|error| anyhow!("{error}"))?;
        ensure!(remaining.is_empty(), "trailing bytes in certificate");
        let common_name = cert
            .subject()
            .iter_common_name()
            .last()
            .and_then(|name| name.as_str().ok())
            .unwrap_or_default()
            .to_owned();
        let dns_names = cert
            .subject_alternative_name()
            .map_err(|error| anyhow!("{error}"))?
            .map(|extension| {
                extension
                    .value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        GeneralName::DNSName(name) => Some((*name).to_owned()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut signature_algorithm =
            match cert.signature_algorithm.algorithm.to_id_string().as_str() {
                "1.2.840.113549.1.1.4" => "MD5-RSA",
                "1.2.840.113549.1.1.5" => "SHA1-RSA",
                "1.2.840.113549.1.1.11" => "SHA256-RSA",
                "1.2.840.113549.1.1.12" => "SHA384-RSA",
                "1.2.840.113549.1.1.13" => "SHA512-RSA",
                "1.2.840.113549.1.1.10" => "0",
                "1.2.840.10040.4.3" => "DSA-SHA1",
                "2.16.840.1.101.3.4.3.2" => "DSA-SHA256",
                "1.2.840.10045.4.1" => "ECDSA-SHA1",
                "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
                "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
                "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
                "1.3.101.112" => "Ed25519",
                _ => "0",
            }
            .to_owned();
        if let Ok(x509_parser::signature_algorithm::SignatureAlgorithm::RSASSA_PSS(parameters)) =
            x509_parser::signature_algorithm::SignatureAlgorithm::try_from(
                &cert.signature_algorithm,
            )
        {
            signature_algorithm = match parameters.hash_algorithm_oid().to_id_string().as_str() {
                "2.16.840.1.101.3.4.2.1" => "SHA256-RSAPSS",
                "2.16.840.1.101.3.4.2.2" => "SHA384-RSAPSS",
                "2.16.840.1.101.3.4.2.3" => "SHA512-RSAPSS",
                _ => "0",
            }
            .into();
        }
        let public_key_algorithm = match cert
            .public_key()
            .algorithm
            .algorithm
            .to_id_string()
            .as_str()
        {
            "1.2.840.113549.1.1.1" => "RSA",
            "1.2.840.10040.4.1" => "DSA",
            "1.2.840.10045.2.1" => "ECDSA",
            "1.3.101.112" => "Ed25519",
            _ => "0",
        }
        .to_owned();
        Ok(Self {
            raw: raw.to_vec(),
            common_name,
            dns_names,
            signature_algorithm,
            public_key_algorithm,
        })
    }

    pub fn hash(&self) -> String {
        Sha256::digest(&self.raw)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateInfo>> {
    let mut certs = Vec::new();
    if bytes.windows(5).any(|window| window == b"BEGIN") {
        for block in x509_parser::pem::Pem::iter_from_buffer(bytes) {
            let block = block.context("Unable to decode PEM certificate")?;
            certs.push(
                CertificateInfo::parse(&block.contents).context("Unable to decode certificate")?,
            );
        }
    } else {
        let mut input = bytes;
        while !input.is_empty() {
            let (remaining, _) = parse_x509_certificate(input)
                .map_err(|error| anyhow!("Unable to parse certificates: {error}"))?;
            let consumed = input.len() - remaining.len();
            ensure!(
                consumed > 0,
                "Unable to parse certificates: empty certificate"
            );
            certs.push(CertificateInfo::parse(&input[..consumed])?);
            input = remaining;
        }
    }
    Ok(certs)
}

fn hash_output(bytes: &[u8]) -> Result<String> {
    let certs = parse_certificates(bytes)?;
    if certs.is_empty() {
        return Ok("No certificates found\n".into());
    }
    let rows: Vec<_> = certs
        .iter()
        .enumerate()
        .map(|(i, cert)| {
            (
                if i == 0 {
                    "Leaf SHA256:".into()
                } else {
                    format!("CA <{}> SHA256:", cert.common_name)
                },
                cert.hash(),
            )
        })
        .collect();
    Ok(super::table(&rows))
}

pub(super) fn hash_file(path: &Path, out: &mut impl Write) -> Result<()> {
    match fs::read(path)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| hash_output(&bytes))
    {
        Ok(text) => out.write_all(text.as_bytes())?,
        Err(error) => writeln!(out, "{error:#}")?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("fixtures/ca.pem");
    const HASH: &str = "d5fe79e9d06e38478a3fbb5ead57c498af09298747984fb88182a4f540c01244";

    fn args(ca: bool) -> CertArgs {
        CertArgs {
            domain: vec!["example.com".into(), "127.0.0.1".into()],
            name: "Test Name".into(),
            org: "Test Org".into(),
            ca,
            json: true,
            file: String::new(),
            expire: "240h".into(),
        }
    }

    #[test]
    fn go_certificate_hash_fixture_and_der_chain() {
        assert_eq!(
            hash_output(FIXTURE).unwrap(),
            format!("Leaf SHA256:  {HASH}\n")
        );
        let cert = parse_certificates(FIXTURE).unwrap().remove(0);
        assert_eq!(cert.common_name, "CLI Fixture");
        assert_eq!(cert.signature_algorithm, "ECDSA-SHA256");
        assert_eq!(cert.public_key_algorithm, "ECDSA");
        assert_eq!(cert.dns_names, ["fixture.example"]);
        assert_eq!(
            hash_output(&cert.raw).unwrap(),
            hash_output(FIXTURE).unwrap()
        );
        let mut chain = cert.raw.clone();
        chain.extend_from_slice(&cert.raw);
        assert_eq!(
            hash_output(&chain).unwrap(),
            format!("Leaf SHA256:              {HASH}\nCA <CLI Fixture> SHA256:  {HASH}\n")
        );
    }

    #[test]
    fn generated_certificate_profile_matches_source() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        for ca in [false, true] {
            let (der, key) = create(&args(ca), now).unwrap();
            let (_, cert) = parse_x509_certificate(&der).unwrap();
            assert_eq!(
                cert.validity().not_before.timestamp(),
                now.unix_timestamp() - 3600
            );
            assert_eq!(
                cert.validity().not_after.timestamp(),
                now.unix_timestamp() + 864_000
            );
            assert_eq!(cert.basic_constraints().unwrap().unwrap().value.ca, ca);
            let usage = cert.key_usage().unwrap().unwrap().value;
            assert!(usage.digital_signature() && usage.key_encipherment());
            assert_eq!(usage.key_cert_sign(), ca);
            assert!(
                cert.extended_key_usage()
                    .unwrap()
                    .unwrap()
                    .value
                    .server_auth
            );
            assert_eq!(
                CertificateInfo::parse(&der).unwrap().dns_names,
                ["example.com", "127.0.0.1"]
            );
            assert!(key.len() > 100);
            assert!(cert.raw_serial().len() <= 17);
        }
    }

    #[test]
    fn json_preserves_go_pem_label_and_line_arrays() {
        let mut output = Vec::new();
        generate(&args(false), &mut output).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["certificate"][0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(value["key"][0], "-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(output.last(), Some(&b'\n'));
    }

    #[test]
    fn duration_matches_go_units_fractions_and_limits() {
        for (text, nanos) in [
            ("0", 0),
            ("1h30m", 5_400_000_000_000),
            ("-.5s", -500_000_000),
            ("1.s", 1_000_000_000),
            ("1Âµs2Î¼s3us", 6000),
            ("1.0000000009s", 1_000_000_000),
            ("9223372036854775807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
        ] {
            assert_eq!(
                duration(text).unwrap().whole_nanoseconds(),
                nanos as i128,
                "{text}"
            );
        }
        for text in [
            "",
            "+",
            "1",
            ".s",
            "1d",
            "1 s",
            "9223372036854775808ns",
            "-9223372036854775809ns",
            "1s-2s",
        ] {
            assert!(duration(text).is_err(), "accepted {text}");
        }
    }

    #[test]
    fn malformed_certificates_and_empty_inputs() {
        assert_eq!(hash_output(b"").unwrap(), "No certificates found\n");
        assert!(hash_output(b"not DER").is_err());
        assert!(hash_output(super::super::pem("CERTIFICATE", b"not DER").as_bytes()).is_err());
        let mut truncated = parse_certificates(FIXTURE).unwrap().remove(0).raw;
        truncated.pop();
        assert!(hash_output(&truncated).is_err());
        let mut bad_args = args(false);
        bad_args.domain = vec![String::new()];
        assert!(create(&bad_args, OffsetDateTime::now_utc()).is_err());
    }
}
