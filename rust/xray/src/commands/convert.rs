//! The `convert` CLI: TypedMessage ↔ JSON tools, from
//! `main/commands/all/convert`.
//!
//! `convert json` decodes one TypedMessage (`{"type": "...", "value": "<base64>"}`
//! — the form the api add-commands print) into reflection JSON: proto field
//! names in their JSON spellings, bytes as base64, with the
//! `_TypedMessage_` type annotation when `-type` is set. `convert pb` (JSON
//! configs merged into a core.Config protobuf) requires the full
//! config-to-protobuf encoder, which is not integrated; it fails with a
//! named error rather than emitting a partial file.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use clap::{Args, Subcommand};
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde_json::Value;
use std::io::Read as _;

/// The pool built once from the full descriptor set the proto crate embeds.
fn pool() -> Result<DescriptorPool> {
    static POOL: std::sync::OnceLock<Result<DescriptorPool, String>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(xray_proto::FILE_DESCRIPTOR_SET)
            .map_err(|error| format!("decode the descriptor set: {error}"))
    })
    .clone()
    .map_err(anyhow::Error::msg)
    .context("build the protobuf descriptor pool")
}

#[derive(Clone, Debug, Args)]
pub struct ConvertArgs {
    #[command(subcommand)]
    pub command: ConvertCommand,
}

#[derive(Clone, Debug, Subcommand)]
pub enum ConvertCommand {
    /// Convert one TypedMessage file to reflection JSON.
    Json {
        /// Insert the `_TypedMessage_` type annotation into the output.
        #[arg(short = 't', long)]
        r#type: bool,
        /// The TypedMessage file (JSON: {"type", "value"}).
        input: String,
    },
    /// Convert JSON configs to a core.Config protobuf (not integrated).
    #[command(name = "pb")]
    Protobuf {
        /// The protobuf output file.
        #[arg(short = 'o', long = "outpbfile")]
        out_pb_file: Option<String>,
        /// Show the merged config as JSON (debugging only).
        #[arg(short = 'd', long)]
        debug: bool,
        /// The JSON config files to merge.
        configs: Vec<String>,
    },
}

pub fn execute(command: ConvertCommand) -> Result<String> {
    match command {
        ConvertCommand::Json { r#type, input } => {
            let raw = read_input(&input)?;
            let typed: TypedMessageFile = serde_json::from_str(&raw)
                .with_context(|| format!("failed to unmarshal the TypedMessage from {input}"))?;
            let json = typed_message_to_json(&typed, r#type)?;
            Ok(format!("{}\n", serde_json::to_string_pretty(&json)?))
        }
        ConvertCommand::Protobuf {
            out_pb_file,
            debug,
            configs,
        } => {
            let _ = (out_pb_file, debug, configs);
            bail!(
                "convert pb requires the full config-to-protobuf encoder, \\
                 which is not integrated in this CLI build"
            );
        }
    }
}

/// The TypedMessage wire form Go's api commands print and consume.
#[derive(serde::Deserialize)]
struct TypedMessageFile {
    r#type: String,
    value: String,
}

fn read_input(input: &str) -> Result<String> {
    if input == "stdin:" || input == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("read the TypedMessage from stdin")?;
        return Ok(buffer);
    }
    std::fs::read_to_string(input).with_context(|| format!("failed to load {input}"))
}

/// Decode one TypedMessage into reflection JSON via the descriptor pool
/// (Go's `reflect.MarshalToJson`): the message's descriptor-driven fields
/// in their proto-JSON spellings, with the type annotation when requested.
fn typed_message_to_json(typed: &TypedMessageFile, insert_type: bool) -> Result<Value> {
    let pool = pool()?;
    let full_name = typed
        .r#type
        .trim_start_matches("type.googleapis.com/")
        .to_owned();
    let descriptor = pool
        .get_message_by_name(&full_name)
        .with_context(|| format!("the protobuf type {full_name:?} is not in the descriptor set"))?;
    let value = base64::engine::general_purpose::STANDARD
        .decode(typed.value.as_bytes())
        .context("decode the TypedMessage's base64 value")?;
    let message = DynamicMessage::decode(descriptor, value.as_slice())
        .with_context(|| format!("decode the {full_name} message"))?;
    let mut json = serde_json::to_value(&message)
        .with_context(|| format!("marshal the {full_name} message to JSON"))?;
    if let Value::Object(map) = &mut json
        && insert_type
    {
        map.insert("_TypedMessage_".into(), Value::String(typed.r#type.clone()));
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[test]
    fn typed_messages_decode_through_the_descriptor_pool() {
        // A socks ServerConfig: the type resolves in the embedded descriptor
        // set and the payload decodes to reflection JSON.
        let socks = xray_proto::xray::proxy::socks::ServerConfig::default();
        let typed = TypedMessageFile {
            r#type: "type.googleapis.com/xray.proxy.socks.ServerConfig".into(),
            value: STANDARD.encode(prost::Message::encode_to_vec(&socks)),
        };
        let json = typed_message_to_json(&typed, false).unwrap();
        assert!(json.is_object());

        // Unknown type names fail with the descriptor error, not a panic.
        let typed = TypedMessageFile {
            r#type: "type.googleapis.com/not.a.RealMessage".into(),
            value: STANDARD.encode([]),
        };
        assert!(typed_message_to_json(&typed, false).is_err());

        // Malformed base64 fails at the value decode.
        let typed = TypedMessageFile {
            r#type: "type.googleapis.com/xray.proxy.socks.ServerConfig".into(),
            value: "!!not base64!!".into(),
        };
        assert!(typed_message_to_json(&typed, false).is_err());
    }
}
