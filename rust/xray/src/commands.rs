//! Native implementations of the remaining `main/commands/all` utilities.
//!
//! Embed [`Command`] with `#[command(flatten)]` in the executable's Clap
//! subcommand enum, then dispatch it through [`execute`]. Randomness comes from
//! the operating system; deterministic seed helpers are tested against the Go
//! executable's output, not a second invocation of the Rust implementation.

pub mod api;
mod certificate;
mod convert;
mod ech;
mod ping;
mod post_quantum;

use std::{io::Write, path::PathBuf};

use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum Command {
    /// Call the implemented management APIs of an Xray process.
    Api {
        #[command(subcommand)]
        command: api::ApiCommand,
    },
    /// Convert configuration formats.
    Convert {
        #[command(subcommand)]
        command: convert::ConvertCommand,
    },
    /// Generate an ML-KEM-768 key pair for VLESS Encryption.
    Mlkem768(SeedArgs),
    /// Generate an ML-DSA-65 signing seed and REALITY verification key.
    Mldsa65(SeedArgs),
    /// Generate VLESS decryption/encryption configuration pairs.
    Vlessenc,
    /// TLS certificate, ECH, certificate hash, and handshake utilities.
    Tls {
        #[command(subcommand)]
        command: TlsCommand,
    },
}

#[derive(Args)]
pub struct SeedArgs {
    /// Seed encoded as unpadded URL-safe base64.
    #[arg(short = 'i', default_value = "")]
    pub input: String,
}

#[derive(Subcommand)]
pub enum TlsCommand {
    /// Generate a self-signed ECDSA P-256 certificate and private key.
    Cert(CertArgs),
    /// Generate or restore TLS ECH configuration and server keys.
    Ech(EchArgs),
    /// Calculate SHA-256 hashes of complete DER certificates.
    Hash {
        #[arg(long, default_value = "fullchain.pem")]
        cert: PathBuf,
    },
    /// Connect with and without SNI and inspect the TLS handshake.
    Ping {
        #[arg(long, default_value = "")]
        ip: String,
        domain: String,
    },
}

#[derive(Args)]
pub struct CertArgs {
    #[arg(long, action = clap::ArgAction::Append)]
    pub domain: Vec<String>,
    #[arg(long, default_value = "Xray Inc")]
    pub name: String,
    #[arg(long, default_value = "Xray Inc")]
    pub org: String,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub ca: bool,
    #[arg(long, default_value_t = true, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub json: bool,
    #[arg(long, default_value = "")]
    pub file: String,
    #[arg(long, default_value = "2160h")]
    pub expire: String,
}

#[derive(Args)]
pub struct EchArgs {
    #[arg(long = "serverName", default_value = "cloudflare-ech.com")]
    pub server_name: String,
    #[arg(long, default_value_t = false, num_args = 0..=1, require_equals = true, default_missing_value = "true", action = clap::ArgAction::Set)]
    pub pem: bool,
    #[arg(short = 'i', default_value = "")]
    pub input: String,
}

pub fn execute(command: Command) -> Result<()> {
    execute_to(command, &mut std::io::stdout().lock())
}

/// Output injection keeps printing and filesystem/network side effects
/// separately testable and makes broken-pipe errors visible to the caller.
pub fn execute_to(command: Command, out: &mut impl Write) -> Result<()> {
    match command {
        Command::Api { command } => {
            let output = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(api::execute(command))?;
            out.write_all(output.as_bytes())?;
        }
        Command::Convert { command } => {
            let output = convert::execute(command)?;
            out.write_all(output.as_bytes())?;
        }
        Command::Mlkem768(args) => {
            out.write_all(post_quantum::mlkem768(&args.input)?.as_bytes())?
        }
        Command::Mldsa65(args) => out.write_all(post_quantum::mldsa65(&args.input)?.as_bytes())?,
        Command::Vlessenc => out.write_all(post_quantum::vlessenc()?.as_bytes())?,
        Command::Tls { command } => match command {
            TlsCommand::Cert(args) => certificate::generate(&args, out)?,
            TlsCommand::Ech(args) => out.write_all(ech::run(&args)?.as_bytes())?,
            TlsCommand::Hash { cert } => certificate::hash_file(&cert, out)?,
            TlsCommand::Ping { ip, domain } => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(ping::run(&domain, &ip, out))?,
        },
    }
    Ok(())
}

/// Go's PEM writer uses 64-column base64 and a final LF. In particular the
/// certificate command deliberately labels PKCS#8 bytes "RSA PRIVATE KEY".
fn pem(label: &str, bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let encoded = STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Equivalent to a tabwriter with two spaces of padding for the single-tab
/// tables used by `tls hash` and `tls ping`.
fn table(rows: &[(String, String)]) -> String {
    let width = rows
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0)
        + 2;
    let mut out = String::new();
    for (label, value) in rows {
        out.push_str(label);
        out.extend(std::iter::repeat_n(' ', width - label.chars().count()));
        out.push_str(value);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: Command,
    }

    #[test]
    fn clap_preserves_source_command_names_and_boolean_values() {
        assert!(matches!(
            TestCli::try_parse_from(["xray", "api", "statsquery", "--pattern=traffic"])
                .unwrap()
                .command,
            Command::Api {
                command: api::ApiCommand::StatsQuery(_)
            }
        ));
        assert!(matches!(
            TestCli::try_parse_from(["xray", "mlkem768"])
                .unwrap()
                .command,
            Command::Mlkem768(_)
        ));
        assert!(matches!(
            TestCli::try_parse_from(["xray", "mldsa65"])
                .unwrap()
                .command,
            Command::Mldsa65(_)
        ));
        assert!(matches!(
            TestCli::try_parse_from(["xray", "vlessenc"])
                .unwrap()
                .command,
            Command::Vlessenc
        ));
        let cli = TestCli::try_parse_from([
            "xray",
            "tls",
            "cert",
            "--domain=example.com",
            "--domain=example.net",
            "--ca",
            "--json=false",
        ])
        .unwrap();
        let Command::Tls {
            command: TlsCommand::Cert(cert),
        } = cli.command
        else {
            panic!("not a certificate command");
        };
        assert!(cert.ca);
        assert!(!cert.json);
        assert_eq!(cert.domain, ["example.com", "example.net"]);
        let cli = TestCli::try_parse_from([
            "xray",
            "tls",
            "ech",
            "--serverName",
            "example.com",
            "--pem=false",
        ])
        .unwrap();
        let Command::Tls {
            command: TlsCommand::Ech(ech),
        } = cli.command
        else {
            panic!("not an ECH command");
        };
        assert_eq!(ech.server_name, "example.com");
        assert!(!ech.pem);
        assert!(TestCli::try_parse_from(["xray", "tls", "ping"]).is_err());
    }

    #[test]
    fn invalid_seed_message_is_successful_stdout_output() {
        let mut out = Vec::new();
        execute_to(
            Command::Mlkem768(SeedArgs {
                input: "invalid".into(),
            }),
            &mut out,
        )
        .unwrap();
        assert_eq!(out, b"Invalid length ML-KEM-768 seed.\n");
    }
}
