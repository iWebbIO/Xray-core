use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use clap::{Args, Parser, Subcommand};
use rand::RngCore;
use xray_core::{Config, Server};

mod commands;
mod config_loader;

#[derive(Parser)]
#[command(
    name = "xray",
    version,
    about = "Xray native Rust migration (see rust/MIGRATION.md for feature coverage)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy or validate configuration.
    Run(Run),
    /// Print implementation and source compatibility versions.
    Version,
    /// Generate a random UUID or a deterministic VLESS user ID.
    Uuid {
        #[arg(short = 'i', default_value = "")]
        input: String,
    },
    /// Generate a REALITY/VLESS X25519 keypair.
    X25519(Keys),
    /// Generate a WireGuard X25519 keypair.
    Wg(Keys),
    #[command(flatten)]
    Utilities(commands::Command),
}

#[derive(Args)]
struct Keys {
    #[arg(short = 'i')]
    input: Option<String>,
    #[arg(long)]
    std_encoding: bool,
}

#[derive(Args)]
struct Run {
    #[arg(short = 'c', long = "config")]
    configs: Vec<PathBuf>,
    #[arg(long)]
    confdir: Option<PathBuf>,
    /// Input format: auto, json/jsonc, yaml/yml, toml, or pb/protobuf.
    #[arg(long, default_value = "auto")]
    format: String,
    #[arg(long)]
    test: bool,
    #[arg(long)]
    dump: bool,
}

fn arguments() -> Vec<OsString> {
    normalize_arguments(std::env::args_os().collect())
}

fn normalize_arguments(mut args: Vec<OsString>) -> Vec<OsString> {
    if args.len() == 1
        || args.get(1).is_some_and(|arg| {
            arg.to_string_lossy().starts_with('-')
                && arg != "--help"
                && arg != "-h"
                && arg != "--version"
                && arg != "-V"
        })
    {
        args.insert(1, "run".into());
    }
    let mut value_next = false;
    for arg in args.iter_mut().skip(2) {
        if value_next {
            value_next = false;
            continue;
        }
        let text = arg.to_string_lossy();
        let flag = text.split('=').next().unwrap_or("");
        value_next = matches!(
            flag,
            "-c" | "-config"
                | "--config"
                | "-confdir"
                | "--confdir"
                | "-format"
                | "--format"
                | "-i"
                | "-domain"
                | "--domain"
                | "-name"
                | "--name"
                | "-org"
                | "--org"
                | "-file"
                | "--file"
                | "-expire"
                | "--expire"
                | "-serverName"
                | "--serverName"
                | "-cert"
                | "--cert"
                | "-ip"
                | "--ip"
                | "-server"
                | "--server"
                | "-s"
                | "-timeout"
                | "--timeout"
                | "-t"
                | "-pattern"
                | "--pattern"
                | "-email"
                | "--email"
        ) && !text.contains('=');
        if matches!(
            flag,
            "-config"
                | "-confdir"
                | "-format"
                | "-test"
                | "-dump"
                | "-std-encoding"
                | "-domain"
                | "-name"
                | "-org"
                | "-ca"
                | "-json"
                | "-file"
                | "-expire"
                | "-serverName"
                | "-pem"
                | "-cert"
                | "-ip"
                | "-server"
                | "-timeout"
                | "-reset"
                | "-pattern"
                | "-email"
                | "-all"
                | "-include-traffic"
        ) {
            *arg = format!("-{text}").into();
        }
    }
    args
}

fn main() {
    let cli = Cli::parse_from(arguments());
    let is_run = matches!(cli.command, Command::Run(_));
    if let Err(error) = execute(cli.command) {
        eprintln!("Xray: {error:#}");
        std::process::exit(if is_run { 23 } else { 1 });
    }
}

fn execute(command: Command) -> Result<()> {
    match command {
        Command::Version => println!(
            "Xray Rust {} (source compatibility target: Xray 26.9.9)\nNative Rust migration; feature parity is in progress.",
            env!("CARGO_PKG_VERSION")
        ),
        Command::Uuid { input } => println!(
            "{}",
            if input.is_empty() {
                uuid::Uuid::new_v4()
            } else {
                ensure!(input.len() <= 30, "Input must be within 30 bytes.");
                xray_core::user::parse_id(&input)?
            }
        ),
        Command::X25519(keys) => print_keys(keys, false)?,
        Command::Wg(keys) => print_keys(keys, true)?,
        Command::Utilities(command) => commands::execute(command)?,
        Command::Run(args) => {
            let merged = config_loader::load(&config_loader::LoadOptions {
                configs: args.configs,
                confdir: args.confdir,
                format: args.format,
            })?;
            if args.dump {
                println!("{}", serde_json::to_string_pretty(&merged)?);
                return Ok(());
            }
            let config: Config = serde_json::from_value(merged)
                .context("invalid or unsupported Xray configuration")?;
            config.validate()?;
            if args.test {
                println!("Configuration OK.");
                return Ok(());
            }
            use tracing_subscriber::prelude::*;
            let logger = xray_core::logging::Logger::from_optional_config(config.log.as_ref())?;
            tracing_subscriber::registry()
                .with(logger.tracing_layer())
                .try_init()
                .map_err(|e| anyhow::anyhow!("cannot initialize logging: {e}"))?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async move {
                    let mut server = Server::start_with_logger(config, logger).await?;
                    tokio::select! {
                        signal = shutdown_signal() => signal?,
                        result = server.wait() => return result,
                    }
                    server.shutdown().await
                })?;
        }
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => () }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn print_keys(keys: Keys, wireguard: bool) -> Result<()> {
    let encoding = if wireguard || keys.std_encoding {
        &STANDARD
    } else {
        &URL_SAFE_NO_PAD
    };
    let mut private = [0_u8; 32];
    if let Some(input) = keys.input {
        let decoded = encoding
            .decode(input)
            .context("invalid base64 private key")?;
        ensure!(decoded.len() == 32, "Invalid length of X25519 private key.");
        private.copy_from_slice(&decoded);
    } else {
        rand::rngs::OsRng.fill_bytes(&mut private);
    }
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let secret = x25519_dalek::StaticSecret::from(private);
    let public = x25519_dalek::PublicKey::from(&secret);
    let hash = blake3::hash(public.as_bytes());
    println!(
        "PrivateKey: {}\nPassword (PublicKey): {}\nHash32: {}",
        encoding.encode(private),
        encoding.encode(public.as_bytes()),
        encoding.encode(hash.as_bytes())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_legacy_flags_without_changing_their_values() {
        let args = ["xray", "-c", "-test", "-test"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert_eq!(
            normalize_arguments(args),
            ["xray", "run", "-c", "-test", "--test"].map(OsString::from)
        );
        let args = ["xray", "run", "-config=example.json", "-test"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert!(Cli::try_parse_from(normalize_arguments(args)).is_ok());
    }
}
