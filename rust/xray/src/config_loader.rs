//! Load and merge human-edited Xray configuration without validating runtime features.
//!
//! Ordering and overrides follow `main/run.go` and `infra/conf/xray.go`. Local
//! JSON/JSONC, YAML, TOML and single-file protobuf inputs are supported. Binary
//! protobuf input stays bytes until native decoding. Remote HTTP/Unix-socket
//! inputs fail explicitly here.
//! YAML uses the parser's YAML 1.2 scalar resolution: unlike Go's YAML 1.1
//! decoder, unquoted `yes`, `no`, `on` and `off` remain strings. Quoted strings
//! are never heuristically converted. Unknown configuration fields are retained
//! for the downstream validator, including fields outside today's Rust models.

use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Number, Value};

/// Command-line inputs. Repeated config paths retain their original order;
/// matching confdir entries are sorted and appended after them.
#[derive(Clone, Debug)]
pub struct LoadOptions {
    pub configs: Vec<PathBuf>,
    pub confdir: Option<PathBuf>,
    /// `auto` infers each input independently; json/jsonc, yaml/yml and toml
    /// and pb/protobuf force that decoder. Unrecognized values fall back to
    /// auto, like Go. Protobuf accepts exactly one input and cannot be merged.
    pub format: String,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            configs: Vec::new(),
            confdir: None,
            format: "auto".into(),
        }
    }
}

/// Load raw configuration values. This does not apply the `env` section or
/// deserialize a runtime `Config`; those operations belong to the caller.
pub fn load(options: &LoadOptions) -> Result<Value> {
    let environment = LoadEnvironment::current();
    load_with(options, &environment, &mut std::io::stdin().lock())
}

#[derive(Debug, Default)]
struct LoadEnvironment {
    working_dir: Option<PathBuf>,
    config_dir: Option<PathBuf>,
    confdir: Option<PathBuf>,
    strict_json: bool,
}

impl LoadEnvironment {
    fn current() -> Self {
        Self {
            working_dir: std::env::current_dir().ok(),
            config_dir: env_flag("xray.location.config", |name| std::env::var_os(name))
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::current_exe()
                        .ok()
                        .and_then(|path| path.parent().map(Path::to_path_buf))
                }),
            confdir: env_flag("xray.location.confdir", |name| std::env::var_os(name))
                .map(PathBuf::from),
            strict_json: env_flag("xray.json.strict", |name| std::env::var_os(name))
                .is_some_and(|value| value == "true"),
        }
    }
}

fn env_flag(name: &str, mut lookup: impl FnMut(&str) -> Option<OsString>) -> Option<OsString> {
    // An explicitly set empty primary variable also wins over the alias.
    lookup(name).or_else(|| lookup(&name.replace('.', "_").to_ascii_uppercase()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Format {
    Json,
    Yaml,
    Toml,
    Protobuf,
}

impl Format {
    fn by_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "json" | "jsonc" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            "pb" | "protobuf" => Some(Self::Protobuf),
            _ => None,
        }
    }

    fn for_source(path: &Path, requested: &str) -> Result<Self> {
        ensure_local_source(path)?;
        let format = Self::by_name(requested)
            .or_else(|| {
                if is_stdin(path) {
                    Some(Self::Json)
                } else {
                    // core.GetFormat uses the final dot, including a leading
                    // dot in an explicitly supplied filename such as `.json`.
                    path.to_string_lossy()
                        .rsplit_once('.')
                        .and_then(|(_, extension)| Self::by_name(extension))
                }
            })
            .with_context(|| format!("cannot infer configuration format for {}", path.display()))?;
        Ok(format)
    }
}

fn is_stdin(path: &Path) -> bool {
    // `-` is retained as an alias from the Rust CLI; Go uses `stdin:`.
    path == Path::new("stdin:") || path == Path::new("-")
}

fn ensure_local_source(path: &Path) -> Result<()> {
    let source = path.to_string_lossy();
    let remote = source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("http+unix://")
        || source.starts_with('@')
        || (source.starts_with('/') && source.contains(":/"));
    ensure!(
        !remote,
        "{}: remote HTTP/Unix-socket configuration sources are not supported by the local configuration loader",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            !fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()),
            "{}: Unix-socket configuration sources are not supported by the local configuration loader",
            path.display()
        );
    }
    Ok(())
}

fn directory_matches(path: &Path, requested: &str) -> bool {
    // Deliberately case-sensitive, as main/run.go's filename regex is. The
    // source's `jsonc` format alias uses the default (all formats) dir filter.
    let extension = path.extension().and_then(|ext| ext.to_str());
    match requested.to_ascii_lowercase().as_str() {
        "json" => matches!(extension, Some("json" | "jsonc")),
        "yaml" | "yml" => matches!(extension, Some("yaml" | "yml")),
        "toml" => extension == Some("toml"),
        _ => matches!(extension, Some("json" | "jsonc" | "yaml" | "yml" | "toml")),
    }
}

fn sources(options: &LoadOptions, environment: &LoadEnvironment) -> Result<Vec<PathBuf>> {
    let mut paths = options.configs.clone();
    let directory = options
        .confdir
        .as_deref()
        .filter(|path| path.is_dir())
        .or_else(|| environment.confdir.as_deref().filter(|path| path.is_dir()));
    if let Some(directory) = directory {
        let mut entries = fs::read_dir(directory)
            .with_context(|| {
                format!(
                    "cannot read configuration directory {}",
                    directory.display()
                )
            })?
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| {
                format!(
                    "cannot list configuration directory {}",
                    directory.display()
                )
            })?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if directory_matches(&entry.path(), &options.format) {
                // Go also attempts matching directories; the subsequent read
                // then reports the offending path rather than skipping it.
                paths.push(entry.path());
            }
        }
    }
    if !paths.is_empty() {
        return Ok(paths);
    }
    if let Some(directory) = &environment.working_dir {
        for name in [
            "config.json",
            "config.jsonc",
            "config.toml",
            "config.yaml",
            "config.yml",
        ] {
            let path = directory.join(name);
            if file_exists(&path) {
                return Ok(vec![path]);
            }
        }
    }
    if let Some(directory) = &environment.config_dir {
        let path = directory.join("config.json");
        if file_exists(&path) {
            return Ok(vec![path]);
        }
    }
    Ok(vec![PathBuf::from("stdin:")])
}

fn file_exists(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| !metadata.is_dir())
}

fn load_with(
    options: &LoadOptions,
    environment: &LoadEnvironment,
    stdin: &mut impl Read,
) -> Result<Value> {
    let paths = sources(options, environment)?;
    // Determine all decoders before opening/consuming any input, as Go does.
    let formats = paths
        .iter()
        .map(|path| Format::for_source(path, &options.format))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !formats.contains(&Format::Protobuf) || paths.len() == 1,
        "only one protobuf configuration input is allowed; binary and text configurations cannot be merged"
    );
    let mut merged = None;
    let mut used_stdin = false;
    for (path, format) in paths.iter().zip(formats) {
        let input = if is_stdin(path) {
            ensure!(
                !used_stdin,
                "{}: stdin can only be loaded once",
                path.display()
            );
            used_stdin = true;
            let mut bytes = Vec::new();
            stdin
                .read_to_end(&mut bytes)
                .context("cannot read configuration from stdin")?;
            bytes
        } else {
            fs::read(path)
                .with_context(|| format!("cannot read configuration {}", path.display()))?
        };
        let document = decode_bytes(&input, format, environment.strict_json)
            .with_context(|| format!("failed to decode configuration {}", path.display()))?;
        if let Some(base) = &mut merged {
            merge_config(base, document, &path.to_string_lossy())
                .with_context(|| format!("failed to merge configuration {}", path.display()))?;
        } else {
            // The first file is copied directly, including duplicate tags.
            merged = Some(document);
        }
    }
    merged.context("no configuration files found")
}

fn decode_bytes(input: &[u8], format: Format, strict_json: bool) -> Result<Value> {
    if format == Format::Protobuf {
        let config = xray_core::config::protobuf::from_bytes(input)?;
        return serde_json::to_value(config)
            .context("cannot project protobuf configuration into the native configuration model");
    }
    decode(
        std::str::from_utf8(input).context("text configuration is not valid UTF-8")?,
        format,
        strict_json,
    )
}

fn decode(input: &str, format: Format, strict_json: bool) -> Result<Value> {
    let value = match format {
        Format::Json if strict_json => {
            serde_json::from_str(input).context("invalid strict JSON")?
        }
        Format::Json => {
            let text = xray_core::config::strip_comments(input)?;
            // json.Decoder.Decode consumes one value; only strict mode calls
            // json.Unmarshal and rejects trailing documents/content.
            serde_json::Deserializer::from_str(&text)
                .into_iter::<Value>()
                .next()
                .context("empty JSON configuration")?
                .context("invalid JSON/JSONC")?
        }
        Format::Yaml => {
            let mut value: serde_yaml::Value =
                serde_yaml::from_str(input).context("invalid YAML")?;
            value.apply_merge().context("invalid YAML merge key")?;
            yaml_to_json(value)?
        }
        Format::Toml => toml_to_json(input.parse::<toml::Value>().context("invalid TOML")?)?,
        Format::Protobuf => bail!("protobuf configuration must be decoded from bytes"),
    };
    // Go decodes JSON null into its existing empty Config allocation.
    if value.is_null() {
        return Ok(Value::Object(Map::new()));
    }
    ensure!(value.is_object(), "configuration must be an object");
    Ok(value)
}

fn yaml_to_json(value: serde_yaml::Value) -> Result<Value> {
    use serde_yaml::Value as Yaml;
    Ok(match value {
        Yaml::Null => Value::Null,
        Yaml::Bool(value) => Value::Bool(value),
        Yaml::Number(value) => {
            if let Some(number) = value.as_i64() {
                Value::from(number)
            } else if let Some(number) = value.as_u64() {
                Value::from(number)
            } else {
                finite_number(value.as_f64().context("invalid YAML number")?)?
            }
        }
        Yaml::String(value) => Value::String(value),
        Yaml::Sequence(values) => Value::Array(
            values
                .into_iter()
                .map(yaml_to_json)
                .collect::<Result<_>>()?,
        ),
        Yaml::Mapping(values) => {
            let mut object = Map::new();
            for (key, value) in values {
                // ghodss/yaml converts scalar number/bool keys to strings,
                // which matters for e.g. numeric policy levels.
                let key = match yaml_to_json(key)? {
                    Value::String(key) => key,
                    Value::Bool(key) => key.to_string(),
                    Value::Number(key) => key.to_string(),
                    _ => bail!("YAML configuration keys must be strings, numbers or booleans"),
                };
                object.insert(key, yaml_to_json(value)?);
            }
            Value::Object(object)
        }
        Yaml::Tagged(value) => yaml_to_json(value.value)?,
    })
}

fn toml_to_json(value: toml::Value) -> Result<Value> {
    Ok(match value {
        toml::Value::String(value) => Value::String(value),
        toml::Value::Integer(value) => Value::from(value),
        toml::Value::Float(value) => finite_number(value)?,
        toml::Value::Boolean(value) => Value::Bool(value),
        // Serializing toml::Value directly would expose a private tagged
        // datetime object instead of Go's JSON date/time string.
        toml::Value::Datetime(value) => Value::String(value.to_string()),
        toml::Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(toml_to_json)
                .collect::<Result<_>>()?,
        ),
        toml::Value::Table(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| Ok((key, toml_to_json(value)?)))
                .collect::<Result<_>>()?,
        ),
    })
}

fn finite_number(value: f64) -> Result<Value> {
    Number::from_f64(value)
        .map(Value::Number)
        .context("configuration contains a non-finite number")
}

fn merge_config(base: &mut Value, overlay: Value, filename: &str) -> Result<()> {
    let base = base
        .as_object_mut()
        .context("configuration must be an object")?;
    let overlay = overlay
        .as_object()
        .context("configuration must be an object")?;
    for (key, value) in overlay {
        match key.as_str() {
            "inbounds" | "outbounds" => merge_handlers(base, key, value, filename)?,
            "env" if !value.is_null() => {
                let incoming = value.as_object().context("env must be an object")?;
                let existing = base
                    .entry(key.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                if existing.is_null() {
                    *existing = Value::Object(Map::new());
                }
                let existing = existing.as_object_mut().context("env must be an object")?;
                existing.extend(incoming.clone());
            }
            // Config.Override only overwrites non-nil pointers/maps.
            "env" | "log" | "routing" | "dns" | "transport" | "policy" | "api" | "metrics"
            | "stats" | "reverse" | "fakeDns" | "observatory" | "burstObservatory" | "version"
            | "geodata"
                if value.is_null() => {}
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(())
}

fn merge_handlers(
    base: &mut Map<String, Value>,
    key: &str,
    incoming: &Value,
    filename: &str,
) -> Result<()> {
    if incoming.is_null() {
        return Ok(());
    }
    let incoming = incoming
        .as_array()
        .with_context(|| format!("{key} must be an array"))?;
    if incoming.is_empty() {
        return Ok(());
    }
    let current = base.entry(key).or_insert_with(|| Value::Array(Vec::new()));
    if current.is_null() {
        *current = Value::Array(Vec::new());
    }
    let current = current
        .as_array_mut()
        .with_context(|| format!("{key} must be an array"))?;
    let prepend = key == "outbounds" && !filename.to_lowercase().contains("tail");
    let mut prepends = Vec::new();
    for handler in incoming {
        let tag = handler_tag(handler)?;
        let mut found = None;
        for (index, existing) in current.iter().enumerate() {
            if handler_tag(existing)? == tag {
                found = Some(index);
                break;
            }
        }
        if let Some(index) = found {
            current[index] = handler.clone();
        } else if prepend {
            // Do not search these deferred prepends when processing the next
            // handler: Go preserves duplicate new tags within this one file.
            prepends.push(handler.clone());
        } else {
            current.push(handler.clone());
        }
    }
    if !prepends.is_empty() {
        prepends.append(current);
        *current = prepends;
    }
    Ok(())
}

fn handler_tag(handler: &Value) -> Result<&str> {
    ensure!(
        handler.is_object() || handler.is_null(),
        "handler must be an object"
    );
    match handler.get("tag") {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(tag)) => Ok(tag),
        _ => bail!("handler tag must be a string"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        collections::HashMap,
        io::Cursor,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixtures(PathBuf);

    impl Fixtures {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "xray-config-loader-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            path
        }

        fn directory(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir_all(&path).unwrap();
            path
        }
    }

    impl Drop for Fixtures {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn run(options: &LoadOptions, environment: &LoadEnvironment, stdin: &str) -> Result<Value> {
        load_with(options, environment, &mut Cursor::new(stdin))
    }

    fn tags(value: &Value, key: &str) -> Vec<String> {
        value[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| handler_tag(item).unwrap().to_owned())
            .collect()
    }

    #[test]
    fn json_comments_preserve_strings_and_unknown_fields() {
        let input = r##"{ /* block */
            "url": "https://host/path#fragment", // Java line comment
            "newFeature": {"escaped": "\"/* literal */", "enabled": true} # Python comment
        }"##;
        let value = decode(input, Format::Json, false).unwrap();
        assert_eq!(value["url"], "https://host/path#fragment");
        assert_eq!(value["newFeature"]["escaped"], "\"/* literal */");
        assert_eq!(value["newFeature"]["enabled"], true);
        assert!(decode("{\"trailing\": true,}", Format::Json, false).is_err());
    }

    #[test]
    fn strict_json_rejects_comments_and_trailing_documents() {
        assert!(decode("{/*comment*/}", Format::Json, true).is_err());
        assert!(decode("{} {}", Format::Json, true).is_err());
        assert_eq!(decode("{} {}", Format::Json, false).unwrap(), json!({}));
        assert_eq!(decode("null", Format::Json, false).unwrap(), json!({}));
        assert!(decode("[]", Format::Json, false).is_err());
    }

    #[test]
    fn yaml_aliases_merge_keys_and_numeric_policy_keys() {
        let value = decode(
            "defaults: &d {handshake: 4, connIdle: 20}\npolicy:\n  levels:\n    0:\n      <<: *d\n      connIdle: 30\nquoted: 'on'\nboolean: true\n",
            Format::Yaml, false,
        ).unwrap();
        assert_eq!(
            value["policy"]["levels"]["0"],
            json!({"handshake":4,"connIdle":30})
        );
        assert_eq!(value["quoted"], "on");
        assert_eq!(value["boolean"], true);
        // Deliberately record the remaining YAML 1.1 compatibility boundary.
        assert_eq!(
            decode("value: on", Format::Yaml, false).unwrap()["value"],
            "on"
        );
        assert!(decode("value: .nan", Format::Yaml, false).is_err());
    }

    #[test]
    fn toml_tables_dates_and_nonfinite_numbers() {
        let value = decode(
            "date = 1979-05-27\ninstant = 1979-05-27T07:32:00Z\n[[outbounds]]\ntag = 'direct'\nprotocol = 'freedom'\n[outbounds.settings]\ndomainStrategy = 'UseIP'\n",
            Format::Toml, false,
        ).unwrap();
        assert_eq!(value["date"], "1979-05-27");
        assert_eq!(value["instant"], "1979-05-27T07:32:00Z");
        assert_eq!(value["outbounds"][0]["settings"]["domainStrategy"], "UseIP");
        assert!(decode("value = nan", Format::Toml, false).is_err());
        assert!(decode("value = inf", Format::Toml, false).is_err());
    }

    #[test]
    fn replacements_keep_positions_and_new_handlers_follow_source_order() {
        let mut base = json!({
            "inbounds":[{"tag":"a","port":1},{"tag":"b","port":2}],
            "outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"old","protocol":"freedom"}]
        });
        merge_config(
            &mut base,
            json!({
                "inbounds":[{"tag":"b","port":3},{"tag":"c","port":4}],
                "outbounds":[{"tag":"new1"},{"tag":"direct","protocol":"blackhole"},{"tag":"new2"}]
            }),
            "01.json",
        )
        .unwrap();
        assert_eq!(tags(&base, "inbounds"), ["a", "b", "c"]);
        assert_eq!(base["inbounds"][1]["port"], 3);
        assert_eq!(tags(&base, "outbounds"), ["new1", "new2", "direct", "old"]);
        assert_eq!(base["outbounds"][2]["protocol"], "blackhole");
        merge_config(
            &mut base,
            json!({"outbounds":[{"tag":"last"}]}),
            "parent-TAIL/02.json",
        )
        .unwrap();
        assert_eq!(
            tags(&base, "outbounds"),
            ["new1", "new2", "direct", "old", "last"]
        );
    }

    #[test]
    fn duplicate_new_outbound_tags_are_deferred_but_tail_and_inbounds_update() {
        for (key, filename, expected_length) in [
            ("outbounds", "next.json", 3),
            ("outbounds", "next-tail.json", 2),
            ("inbounds", "next.json", 2),
        ] {
            let mut base = json!({key:[{"tag":"old"}]});
            merge_config(
                &mut base,
                json!({key:[{"tag":"new","port":1},{"tag":"new","port":2}]}),
                filename,
            )
            .unwrap();
            assert_eq!(base[key].as_array().unwrap().len(), expected_length);
            if expected_length == 3 {
                assert_eq!(base[key][0]["port"], 1);
                assert_eq!(base[key][1]["port"], 2);
            } else {
                assert_eq!(base[key][1]["port"], 2);
            }
        }
    }

    #[test]
    fn empty_tags_replace_first_match_and_first_document_is_not_deduplicated() {
        let mut base =
            json!({"outbounds":[{"protocol":"freedom"},{"tag":"","protocol":"freedom"}]});
        merge_config(
            &mut base,
            json!({"outbounds":[{"protocol":"blackhole"}]}),
            "next.json",
        )
        .unwrap();
        assert_eq!(base["outbounds"].as_array().unwrap().len(), 2);
        assert_eq!(base["outbounds"][0]["protocol"], "blackhole");
        assert_eq!(base["outbounds"][1]["protocol"], "freedom");
        let options = LoadOptions {
            configs: vec!["stdin:".into()],
            ..Default::default()
        };
        let value = run(
            &options,
            &LoadEnvironment::default(),
            r#"{"outbounds":[{"tag":"same"},{"tag":"same"}]}"#,
        )
        .unwrap();
        assert_eq!(value["outbounds"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn null_and_empty_handlers_do_not_clear_prior_values() {
        let original = json!({"log":{"loglevel":"debug"},"routing":{"rules":[1]},"env":{"A":"a"},"inbounds":[{"tag":"a"}],"outbounds":[{"tag":"b"}]});
        let mut base = original.clone();
        merge_config(
            &mut base,
            json!({"log":null,"routing":null,"env":null,"inbounds":null,"outbounds":[]}),
            "empty.json",
        )
        .unwrap();
        assert_eq!(base, original);
        merge_config(
            &mut base,
            json!({"routing":{},"env":{}}),
            "empty-objects.json",
        )
        .unwrap();
        assert_eq!(base["routing"], json!({}));
        assert_eq!(base["env"], json!({"A":"a"}));
    }

    #[test]
    fn environments_merge_and_other_sections_replace_whole_objects() {
        let mut base = json!({"env":{"A":"one","B":"two"},"dns":{"servers":["old"],"tag":"old"},"futureFeature":{"old":true}});
        merge_config(&mut base, json!({"env":{"A":"new","C":"three"},"dns":{"servers":["new"]},"futureFeature":{"new":true}}), "next.json").unwrap();
        assert_eq!(base["env"], json!({"A":"new","B":"two","C":"three"}));
        assert_eq!(base["dns"], json!({"servers":["new"]}));
        assert_eq!(base["futureFeature"], json!({"new":true}));
    }

    #[test]
    fn mixed_formats_append_sorted_confdir_after_repeated_config_paths() {
        let files = Fixtures::new();
        let first = files.write("first.jsonc", r#"{/*local*/"env":{"KEEP":"yes","ORDER":"first"},"outbounds":[{"tag":"first"}],"futureFeature":{"retained":true}}"#);
        let second = files.write(
            "second.yaml",
            "env: {ORDER: second}\noutbounds: [{tag: second}]\n",
        );
        files.write(
            "conf/90-tail.toml",
            "[env]\nORDER = 'last'\n[[outbounds]]\ntag = 'last'\n",
        );
        files.write(
            "conf/10.json",
            r#"{"env":{"ORDER":"middle"},"outbounds":[{"tag":"middle"}]}"#,
        );
        files.write("conf/00.JSON", "invalid uppercase extension is ignored");
        files.write("conf/readme.txt", "ignored");
        let value = run(
            &LoadOptions {
                configs: vec![first, second],
                confdir: Some(files.0.join("conf")),
                ..Default::default()
            },
            &LoadEnvironment::default(),
            "",
        )
        .unwrap();
        assert_eq!(
            tags(&value, "outbounds"),
            ["middle", "second", "first", "last"]
        );
        assert_eq!(value["env"], json!({"KEEP":"yes","ORDER":"last"}));
        assert_eq!(value["futureFeature"]["retained"], true);
    }

    #[test]
    fn valid_explicit_confdir_wins_and_invalid_one_falls_back_to_environment() {
        let files = Fixtures::new();
        let explicit_file = files.write("explicit/one.json", "{}");
        let env_file = files.write("environment/one.json", "{}");
        let environment = LoadEnvironment {
            confdir: Some(files.0.join("environment")),
            ..Default::default()
        };
        let options = LoadOptions {
            confdir: Some(files.0.join("missing")),
            ..Default::default()
        };
        assert_eq!(sources(&options, &environment).unwrap(), vec![env_file]);
        let options = LoadOptions {
            confdir: Some(files.0.join("explicit")),
            ..Default::default()
        };
        assert_eq!(
            sources(&options, &environment).unwrap(),
            vec![explicit_file]
        );
    }

    #[test]
    fn directory_filters_follow_raw_flag_and_explicit_format_overrides_extension() {
        assert!(directory_matches(Path::new("file.jsonc"), "JSON"));
        assert!(!directory_matches(Path::new("file.toml"), "json"));
        assert!(directory_matches(Path::new("file.toml"), "jsonc"));
        assert!(!directory_matches(Path::new("file.YAML"), "yaml"));
        assert!(directory_matches(Path::new("file.yml"), "yaml"));
        assert_eq!(
            Format::for_source(Path::new("file.YAML"), "auto").unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::for_source(Path::new("file.txt"), "YML").unwrap(),
            Format::Yaml
        );
        assert_eq!(
            Format::for_source(Path::new("file.jsonc"), "unknown").unwrap(),
            Format::Json
        );
        assert_eq!(
            Format::for_source(Path::new(".json"), "auto").unwrap(),
            Format::Json
        );
        assert!(Format::for_source(Path::new("file.txt"), "auto").is_err());
    }

    #[test]
    fn working_directory_defaults_precede_config_location_then_stdin() {
        let files = Fixtures::new();
        let cwd = files.directory("cwd");
        let config_dir = files.directory("configuration-location");
        let environment = LoadEnvironment {
            working_dir: Some(cwd),
            config_dir: Some(config_dir),
            ..Default::default()
        };
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![PathBuf::from("stdin:")]
        );
        let env_config = files.write("configuration-location/config.json", "{}");
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![env_config]
        );
        let yaml = files.write("cwd/config.yaml", "{}");
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![yaml]
        );
        let toml = files.write("cwd/config.toml", "");
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![toml]
        );
        let jsonc = files.write("cwd/config.jsonc", "{}");
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![jsonc]
        );
        let json = files.write("cwd/config.json", "{}");
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![json]
        );
    }

    #[test]
    fn environment_aliases_respect_primary_presence_even_when_empty() {
        let mut environment = HashMap::from([
            ("xray.location.confdir", OsString::from("primary")),
            ("XRAY_LOCATION_CONFDIR", OsString::from("alternate")),
            ("XRAY_JSON_STRICT", OsString::from("true")),
        ]);
        assert_eq!(
            env_flag("xray.location.confdir", |name| environment
                .get(name)
                .cloned()),
            Some("primary".into())
        );
        environment.insert("xray.location.confdir", OsString::new());
        assert_eq!(
            env_flag("xray.location.confdir", |name| environment
                .get(name)
                .cloned()),
            Some(OsString::new())
        );
        environment.remove("xray.location.confdir");
        assert_eq!(
            env_flag("xray.location.confdir", |name| environment
                .get(name)
                .cloned()),
            Some("alternate".into())
        );
        assert_eq!(
            env_flag("xray.json.strict", |name| environment.get(name).cloned()),
            Some("true".into())
        );
    }

    #[test]
    fn stdin_is_used_once_and_obeys_forced_format_and_strict_mode() {
        assert_eq!(
            run(&LoadOptions::default(), &LoadEnvironment::default(), "{}").unwrap(),
            json!({})
        );
        let options = LoadOptions {
            configs: vec!["-".into()],
            format: "yaml".into(),
            ..Default::default()
        };
        assert_eq!(
            run(&options, &LoadEnvironment::default(), "newFeature: true").unwrap(),
            json!({"newFeature":true})
        );
        let options = LoadOptions {
            configs: vec!["stdin:".into(), "-".into()],
            ..Default::default()
        };
        assert!(
            format!(
                "{:#}",
                run(&options, &LoadEnvironment::default(), "{}").unwrap_err()
            )
            .contains("stdin can only be loaded once")
        );
        let strict = LoadEnvironment {
            strict_json: true,
            ..Default::default()
        };
        assert!(run(&LoadOptions::default(), &strict, "{/*comment*/}").is_err());
    }

    #[test]
    fn errors_identify_source_and_unsupported_source_types() {
        for name in [
            "https://example.test/config.json",
            "http+unix:///tmp/api.sock/config",
            "@abstract:/config",
            "/tmp/api.sock:/config",
        ] {
            let error = Format::for_source(Path::new(name), "auto")
                .unwrap_err()
                .to_string();
            assert!(error.contains(name), "{error}");
            assert!(error.contains("not supported"), "{error}");
        }
        let files = Fixtures::new();
        let bad = files.write("broken.json", "{\"inbounds\": [}");
        let options = LoadOptions {
            configs: vec![bad.clone()],
            ..Default::default()
        };
        let error = format!(
            "{:#}",
            run(&options, &LoadEnvironment::default(), "").unwrap_err()
        );
        assert!(error.contains(&bad.display().to_string()), "{error}");
        assert!(error.contains("line 1"), "{error}");
    }

    #[test]
    fn protobuf_file_and_forced_stdin_preserve_non_utf8_bytes() {
        let bytes = include_bytes!("../../fixtures/protobuf/basic.pb");
        assert!(std::str::from_utf8(bytes).is_err());
        let files = Fixtures::new();
        for extension in ["pb", "protobuf"] {
            let path = files.0.join(format!("native.{extension}"));
            fs::write(&path, bytes).unwrap();
            let config = load_with(
                &LoadOptions {
                    configs: vec![path],
                    ..Default::default()
                },
                &LoadEnvironment::default(),
                &mut Cursor::new([]),
            )
            .unwrap();
            assert_eq!(
                config["outbounds"][1]["settings"]["response"]["customResponseData"],
                "/wABgA=="
            );
            assert_eq!(config["policy"]["levels"]["0"]["handshake"], 0);
        }
        for format in ["pb", "protobuf", "PROTOBUF"] {
            let config = load_with(
                &LoadOptions {
                    configs: vec!["stdin:".into()],
                    format: format.into(),
                    ..Default::default()
                },
                &LoadEnvironment::default(),
                &mut Cursor::new(bytes),
            )
            .unwrap();
            assert_eq!(config["outbounds"][0]["protocol"], "freedom");
        }
        assert_eq!(
            Format::for_source(Path::new("input.data"), "pb").unwrap(),
            Format::Protobuf
        );
        assert_eq!(
            Format::for_source(Path::new("stdin:"), "auto").unwrap(),
            Format::Json
        );
    }

    #[test]
    fn protobuf_multi_source_rejection_precedes_consumption_and_defaults_stay_textual() {
        for paths in [
            vec!["stdin:".into(), "second.pb".into()],
            vec!["first.pb".into(), "second.json".into()],
        ] {
            let mut input = Cursor::new(b"unconsumed");
            let error = load_with(
                &LoadOptions {
                    configs: paths,
                    ..Default::default()
                },
                &LoadEnvironment::default(),
                &mut input,
            )
            .unwrap_err();
            assert!(error.to_string().contains("only one protobuf"), "{error:#}");
            assert_eq!(input.position(), 0);
        }
        let files = Fixtures::new();
        fs::write(
            files.0.join("config.pb"),
            include_bytes!("../../fixtures/protobuf/basic.pb"),
        )
        .unwrap();
        let environment = LoadEnvironment {
            working_dir: Some(files.0.clone()),
            ..Default::default()
        };
        assert_eq!(
            sources(&LoadOptions::default(), &environment).unwrap(),
            vec![PathBuf::from("stdin:")]
        );
        assert!(!directory_matches(Path::new("config.pb"), "auto"));
        assert!(!directory_matches(Path::new("config.pb"), "pb"));
        let options = LoadOptions {
            configs: vec!["stdin:".into()],
            format: "pb".into(),
            ..Default::default()
        };
        let error = load_with(
            &options,
            &LoadEnvironment::default(),
            &mut Cursor::new([0xff]),
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("stdin:") && error.contains("protobuf"),
            "{error}"
        );
    }
}
