// P40 yaml_env_compat: agent-owned implementation file; stub created for the parallel batch.
#![allow(dead_code)]
//! Go YAML-1.1 scalar semantics and config env handling for the Rust config layer.
//!
//! Go reference chain (all verified in this repo's source):
//!
//! * `infra/conf/serial/loader.go` `DecodeYAMLConfig` reads the whole file and
//!   calls `github.com/ghodss/yaml` `YAMLToJSON` (go.mod pins
//!   `v1.0.1-0.20220118164431-d8423dcdf344`, which wraps `gopkg.in/yaml.v2`
//!   `v2.4.0`), then decodes the resulting JSON with `DecodeJSONConfig` (the
//!   comment-stripping reader in `infra/conf/json/reader.go` plus
//!   `encoding/json`). The YAML layer therefore has exactly yaml.v2's YAML 1.1
//!   plain-scalar resolution, serialized through `json.Marshal`.
//! * Env handling is the root `"env"` object only:
//!   `infra/conf/xray.go` `EnvConfig` (`map[string]string`, json tag `"env"`)
//!   applied in `Config.Build` via `os.Setenv` before post-processing and every
//!   sub-config build, and merged across config files by `EnvConfig.Override`
//!   (later files win). There is **no** `${VAR}` expansion of config values
//!   anywhere in the Go tree (repo-wide grep for `ExpandEnv`/`${` outside
//!   vendor: zero hits), so such strings pass through literally.
//!
//! yaml.v2 scalar behavior ported here (from `gopkg.in/yaml.v2@v2.4.0/resolve.go`
//! plus an empirical probe of the exact ghodss commit):
//!
//! * Booleans: `y Y yes Yes YES true True TRUE on On ON` and
//!   `n N no No NO false False FALSE off Off OFF` (exact casings only) - the
//!   single-letter forms included. serde_yaml 0.9 (YAML 1.2) keeps `yes/on/...`
//!   as strings, so [`normalize_yaml_scalars`] restores them.
//! * Integers: `strconv.ParseInt(s, 0, 64)` after *unconditionally* stripping
//!   all `_` (`1_000`→1000, `0x_1F`→31, `-_5`→-5, `1__0`→10), i.e. base-0
//!   prefixes `0x/0X`, `0o/0O`, `0b/0B`, legacy leading-zero octal
//!   (`010`→8, `0777`→511), overflow falling to `ParseUint` (u64). Invalid
//!   octal like `08` still parses as a float (`8`), `00` is `0`.
//! * Floats: yaml.v2's `^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`
//!   followed by Go `ParseFloat`. Rust's `f64::from_str` accepts the same
//!   shapes for plain forms (including trailing-dot mantissas like `12.` and
//!   `5.e2`), so those agree with serde_yaml upstream; the YAML-1.1-only
//!   float forms needing repair are the underscore variants (`.5_0`→0.5,
//!   `1.5_0`→1.5), where Go accepts underscores between digits. Out-of-range
//!   results (`1e400`) are strings in Go (`ParseFloat` returns an error) and
//!   stay strings here. `json.Marshal` renders integral floats without a
//!   fraction (`1e3`→`1000`), so f64 numbers are canonicalized to integers.
//!   Non-finite scalars (`.inf`, `.nan`) are *not* converted: Go's
//!   `json.Marshal` rejects ±Inf/NaN ("json: unsupported value"), and
//!   serde_yaml 0.9 + serde_json likewise fail ("number out of range")
//!   before normalization ever sees a value - parity of rejection.
//! * Timestamps: yaml.v2 resolves them, but when decoding into `interface{}`
//!   (which is what ghodss/yaml does) it deliberately keeps them as strings
//!   (decode.go's `TODO(v3) Drop this` backward-compat branch; verified
//!   empirically: plain `2022-01-01` stays the string `"2022-01-01"`).
//!   Normalization therefore leaves date-like scalars as strings.
//! * Sexagesimal: YAML 1.1 base-60 (`190:20:30`) is "purposefully unsupported"
//!   in yaml.v2 resolve.go and stays a string - verified. No conversion.
//! * Quoted scalars are always strings in Go. serde_yaml 0.9 agrees for every
//!   scalar form it can parse (YAML 1.2 core: null/true/false variants,
//!   decimal, lowercase `0x/0o/0b`, Rust-parseable finite floats including
//!   trailing-dot mantissas): if such a form arrives as a JSON *string* it
//!   can only have been quoted, so it is preserved. Only scalars serde_yaml
//!   0.9 treats as strings (the YAML-1.1 only forms: `yes`, `1_000`, `010`,
//!   `0X1F`, `.5_0` ...) are re-resolved - which unavoidably also converts
//!   an explicitly quoted `yes`/`1_000` etc. (quote information is lost after
//!   parsing to `serde_json::Value`). This is the documented, unavoidable
//!   deviation of post-parse normalization.
//!
//! Not ported (documented gaps, all outside scalar semantics):
//!
//! * Object keys are left untouched. Go stringifies non-string keys
//!   (`on: x` becomes `{"true": "x"}`); serde_yaml keeps `on` as a literal key
//!   and errors on truly typed keys (`true:`), so key divergence happens
//!   upstream of normalization and cannot be repaired here.
//! * YAML merge keys (`<<:`) expand in yaml.v2 but not in serde_yaml 0.9.
//! * Integers beyond u64/i64: Go resolves e.g. `99999999999999999999` to a
//!   float, serde_yaml's u128 path errors before normalization.
//! * TOML configs (`DecodeTOMLConfig`) are a separate loader, unaffected here.
//!
//! Env decoding (`encoding/json` into `map[string]string`, verified by probe):
//! string values pass through, `null` values decode as empty strings, missing
//! `env` is fine (`"env": null` is a nil map), but any number/bool/array/object
//! value makes Go reject the whole config ("cannot unmarshal ... into ... of
//! type string"). [`apply_env`] mirrors that: valid sections are consumed
//! (removed from the tree, like Go's `Config` consumes them before building),
//! invalid ones are left in place so downstream config parsing rejects the
//! document exactly like Go; it never expands `${VAR}`.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Number, Value};

/// yaml.v2 `yamlStyleFloat` (resolve.go:84).
static YAML_V2_FLOAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$").unwrap());

/// Restores Go's (yaml.v2 / YAML 1.1) plain-scalar semantics on a config tree
/// that was parsed by serde_yaml 0.9 (YAML 1.2) into a `serde_json::Value`.
///
/// Call it after `serde_yaml::from_str::<serde_json::Value>` and before handing
/// the value to `from_value`. Also idempotent: a second pass changes nothing.
/// See the module documentation for the exact rules and deviations.
pub fn normalize_yaml_scalars(value: &mut Value) {
    normalize_walk(value);
}

/// Applies Go's root `"env"` config handling (`infra/conf/xray.go`)
/// `EnvConfig`/`Config.Build`).
///
/// A valid `env` section (an object whose values are strings or nulls; Go
/// decodes nulls as empty strings) is consumed: removed from the tree, with
/// each entry reported through `tracing::debug!`. The caller should read
/// `value["env"]` first if it needs the values; the runtime that owns the
/// environment is expected to set them from that map (Go uses `os.Setenv`).
///
/// An invalid section (non-object, or non-string values) is left in place so
/// the subsequent strict config parse rejects the document, matching Go's
/// `json.Unmarshal` failure for `map[string]string`.
///
/// Go performs **no** `${VAR}` substitution of config values (verified by a
/// repo-wide search: no `os.ExpandEnv` and no `${` handling outside vendor),
/// so this function performs none either; strings like `"${HOME}/path"` pass
/// through literally. `lookup` is only consulted to report the previous value
/// of an applied entry - it never rewrites config text.
pub fn apply_env(value: &mut Value, lookup: &dyn Fn(&str) -> Option<String>) {
    let Some(root) = value.as_object_mut() else {
        return;
    };
    let valid = match root.get("env") {
        None => return,
        Some(Value::Null) => true,
        Some(Value::Object(map)) => map
            .values()
            .all(|v| matches!(v, Value::String(_) | Value::Null)),
        Some(_) => false,
    };
    if !valid {
        tracing::warn!(
            "root \"env\" must be an object with string values; leaving it in place so \
             config parsing rejects the document like Go's map[string]string decode"
        );
        return;
    }
    if let Some(Value::Object(map)) = root.get("env") {
        for (key, entry) in map {
            tracing::debug!(
                key = %key,
                value = %entry,
                previous = ?lookup(key),
                "applying config env entry (Go: os.Setenv in Config.Build)"
            );
        }
    }
    root.remove("env");
}

fn normalize_walk(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for (_key, entry) in map.iter_mut() {
                normalize_walk(entry);
            }
        }
        Value::Array(items) => {
            for entry in items.iter_mut() {
                normalize_walk(entry);
            }
        }
        Value::String(s) => {
            let replaced = normalize_string(s);
            *v = replaced;
        }
        Value::Number(n) => {
            // Go's yaml path marshals integral float64 as plain integers
            // (json.Marshal(1e3) -> "1000"); mirror that on f64 numbers.
            if n.is_f64()
                && let Some(f) = n.as_f64()
            {
                *v = canonical_float(f);
            }
        }
        _ => {}
    }
}

fn normalize_string(s: &str) -> Value {
    // A string that serde_yaml 0.9 itself would have resolved to a non-string
    // scalar can only originate from a quoted scalar, which Go also keeps as
    // a string - preserve it.
    if serde_yaml09_sees_scalar(s) {
        return Value::String(s.to_owned());
    }
    yaml_v2_resolve(s).unwrap_or_else(|| Value::String(s.to_owned()))
}

/// serde_yaml 0.9.34 plain-scalar membership (src/de.rs `visit_untagged_scalar`,
/// `parse_null`, `parse_bool`, `visit_int`, `parse_f64`): true if 0.9 would
/// resolve `s` to null/bool/int/float instead of a string (an int outside the
/// u64/i64 range would make serde_json::Value fail at parse time, but such a
/// scalar then only ever reaches normalization as a quoted string, so it is
/// still "seen" and preserved).
fn serde_yaml09_sees_scalar(s: &str) -> bool {
    if s.is_empty() || matches!(s, "null" | "Null" | "NULL" | "~") {
        return true;
    }
    if matches!(s, "true" | "True" | "TRUE" | "false" | "False" | "FALSE") {
        return true;
    }
    if sy09_unsigned_ok(s, u64::MAX as u128)
        || sy09_negative_ok(s, i64::MIN as i128)
        || sy09_unsigned_ok(s, u128::MAX)
        || sy09_negative_ok(s, i128::MIN)
    {
        return true;
    }
    !digits_but_not_number(s) && sy09_float_ok(s)
}

/// serde_yaml 0.9.34 `digits_but_not_number`: leading-zero integers are
/// strings under YAML 1.2.
fn digits_but_not_number(s: &str) -> bool {
    let s = s.strip_prefix(['-', '+']).unwrap_or(s);
    s.len() > 1 && s.starts_with('0') && s[1..].bytes().all(|b| b.is_ascii_digit())
}

/// serde_yaml 0.9.34 `parse_unsigned_int` (u64/u128 variants via `max`).
fn sy09_unsigned_ok(s: &str, max: u128) -> bool {
    let unpositive = s.strip_prefix('+').unwrap_or(s);
    for (prefix, radix) in [("0x", 16u32), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpositive.strip_prefix(prefix) {
            if rest.starts_with(['+', '-']) {
                return false;
            }
            if let Ok(v) = u128::from_str_radix(rest, radix) {
                return v <= max;
            }
            // A prefixed scalar that failed radix parsing also fails the
            // trailing decimal attempt, so membership is false either way.
            return false;
        }
    }
    if unpositive.starts_with(['+', '-']) {
        return false;
    }
    if digits_but_not_number(s) {
        return false;
    }
    unpositive.parse::<u128>().is_ok_and(|v| v <= max)
}

/// serde_yaml 0.9.34 `parse_negative_int` (i64/i128 variants via `min`).
fn sy09_negative_ok(s: &str, min: i128) -> bool {
    for (prefix, radix) in [("-0x", 16u32), ("-0o", 8), ("-0b", 2)] {
        if let Some(rest) = s.strip_prefix(prefix) {
            let signed = format!("-{rest}");
            if let Ok(v) = i128::from_str_radix(&signed, radix) {
                return v >= min;
            }
            return false;
        }
    }
    if digits_but_not_number(s) {
        return false;
    }
    s.parse::<i128>().is_ok_and(|v| v >= min)
}

/// serde_yaml 0.9.34 `parse_f64`: `.inf`/`.nan` literals and Rust
/// `f64::from_str` on finite values.
fn sy09_float_ok(s: &str) -> bool {
    let unpositive = match s.strip_prefix('+') {
        Some(u) if !u.starts_with(['+', '-']) => u,
        Some(_) => return false,
        None => s,
    };
    if matches!(unpositive, ".inf" | ".Inf" | ".INF") {
        return true;
    }
    if matches!(s, "-.inf" | "-.Inf" | "-.INF") {
        return true;
    }
    if matches!(unpositive, ".nan" | ".NaN" | ".NAN") {
        return true;
    }
    unpositive.parse::<f64>().is_ok_and(f64::is_finite)
}

/// yaml.v2 `resolve` (resolve.go:86-197) for plain scalars, restricted to the
/// classes that survive the serde_yaml 0.9 filter above. Returns the Go value
/// for the scalar, or `None` to keep it a string.
fn yaml_v2_resolve(s: &str) -> Option<Value> {
    let first = *s.as_bytes().first()?;
    // resolveTable hint: only these leading characters can resolve at all.
    let hint = match first {
        b'+' | b'-' => b'S',
        b'0'..=b'9' => b'D',
        b'y' | b'Y' | b'n' | b'N' | b't' | b'T' | b'f' | b'F' | b'o' | b'O' | b'~' => b'M',
        b'.' => b'.',
        _ => return None,
    };
    // resolveMap (resolve.go:32-58): exact casings only; the boolean entries
    // are the only ones reachable here (0.9 already consumed nulls, and
    // non-finite floats cannot be represented in JSON at all).
    match s {
        "y" | "Y" | "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => {
            return Some(Value::Bool(true));
        }
        "n" | "N" | "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => {
            return Some(Value::Bool(false));
        }
        _ => {}
    }
    match hint {
        // Not in the map: stays a string ("y2", "TrUe", "nUll", ...).
        b'M' => None,
        // Go: strconv.ParseFloat on the raw scalar (".5_0" -> 0.5, ".e2" is
        // not a float).
        b'.' => v2_go_float(s).map(canonical_float),
        _ => {
            // Timestamps are *not* attempted here: ghodss/yaml decodes into
            // interface{} and yaml.v2 keeps timestamp-like scalars as strings
            // (verified; see module docs). Underscores are stripped
            // unconditionally before the integer attempts.
            let plain: String = s.chars().filter(|c| *c != '_').collect();
            if let Some(n) = v2_base0_int(&plain) {
                return Some(n);
            }
            if YAML_V2_FLOAT.is_match(&plain) {
                return v2_go_float(&plain).map(canonical_float);
            }
            None
        }
    }
}

/// yaml.v2 'D'/'S' branch: `strconv.ParseInt(plain, 0, 64)` then
/// `strconv.ParseUint(plain, 0, 64)`.
fn v2_base0_int(plain: &str) -> Option<Value> {
    if let Some(i) = v2_parse_base0_i64(plain) {
        return Some(Value::Number(Number::from(i)));
    }
    let u = v2_parse_base0_u64(plain)?;
    Some(Value::Number(Number::from(u)))
}

fn split_sign(s: &str) -> (bool, &str) {
    if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else {
        (false, s)
    }
}

/// Go base-0 body: `0x/0X` hex, `0o/0O` octal, `0b/0B` binary, legacy
/// leading-zero octal, otherwise decimal. Returns `(radix, digits)`.
fn v2_base0_parts(body: &str) -> (u32, &str) {
    for (prefix, radix) in [
        ("0x", 16u32),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(rest) = body.strip_prefix(prefix) {
            return (radix, rest);
        }
    }
    if body.len() > 1 && body.starts_with('0') {
        return (8, body);
    }
    (10, body)
}

fn v2_parse_base0_i64(s: &str) -> Option<i64> {
    let (neg, body) = split_sign(s);
    let (radix, digits) = v2_base0_parts(body);
    let magnitude = u64::from_str_radix(digits, radix).ok()?;
    let signed = if neg {
        0i128.checked_sub(magnitude as i128)?
    } else {
        magnitude as i128
    };
    i64::try_from(signed).ok()
}

fn v2_parse_base0_u64(s: &str) -> Option<u64> {
    // strconv.ParseUint accepts no sign; signed overflow cases were already
    // rejected by the i64 attempt.
    if s.starts_with(['+', '-']) {
        return None;
    }
    let (radix, digits) = v2_base0_parts(s);
    u64::from_str_radix(digits, radix).ok()
}

/// Go `strconv.ParseFloat` behavior for the scalar shapes yaml.v2 feeds it:
/// underscores are accepted only between digits (`.5_0`→0.5, `1.5_0`→1.5;
/// `5__0`/`5_` are not floats), and non-finite results are rejected (yaml.v2
/// only accepts when `err == nil`, so `1e400` stays a string). Rust's
/// `f64::from_str` grammar (`Sign? ( Digit+ | Digit+ '.' Digit* | Digit*
/// '.' Digit+ ) Exp?`) matches Go for everything else, including trailing-dot
/// mantissas (`12.`, `5.e2`) and leading `.`/signs.
fn v2_go_float(s: &str) -> Option<f64> {
    let bytes = s.as_bytes();
    let mut cleaned: Vec<u8> = Vec::with_capacity(s.len());
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
            let next = bytes.get(i + 1).copied();
            if !matches!((prev, next), (Some(p), Some(n)) if p.is_ascii_digit() && n.is_ascii_digit())
            {
                return None;
            }
        } else {
            cleaned.push(b);
        }
    }
    let cleaned = String::from_utf8(cleaned).ok()?;
    let f = cleaned.parse::<f64>().ok()?;
    f.is_finite().then_some(f)
}

/// Go `json.Marshal` for float64: integral values in integer range are emitted
/// without a fraction (`12.0` -> `12`, `1e3` -> `1000`). Non-integral or
/// out-of-range integrals stay f64.
fn canonical_float(f: f64) -> Value {
    if f.is_finite() && f == f.trunc() {
        if (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&f) {
            return Value::Number(Number::from(f as i64));
        }
        if (0.0..18_446_744_073_709_551_616.0).contains(&f) {
            return Value::Number(Number::from(f as u64));
        }
    }
    Number::from_f64(f).map_or(Value::Null, Value::Number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The `input` column below is what serde_yaml 0.9.34 produces for the
    /// given plain YAML scalar (per its src/de.rs; quoted scalars produce the
    /// string form), the `expected` column is Go's ghodss/yaml+yaml.v2 output
    /// verified by running the exact pinned ghodss commit on `k: <scalar>`.
    /// Go probe goldens: `yaml.YAMLToJSON` results.
    #[test]
    fn normalizes_yaml_11_scalars_to_go_semantics() {
        let cases: &[(&str, Value, Value)] = &[
            // YAML 1.1 booleans (serde_yaml 0.9 leaves all of these strings).
            ("yes", json!("yes"), json!(true)),
            ("Yes", json!("Yes"), json!(true)),
            ("YES", json!("YES"), json!(true)),
            ("y", json!("y"), json!(true)),
            ("Y", json!("Y"), json!(true)),
            ("on", json!("on"), json!(true)),
            ("On", json!("On"), json!(true)),
            ("ON", json!("ON"), json!(true)),
            ("no", json!("no"), json!(false)),
            ("No", json!("No"), json!(false)),
            ("NO", json!("NO"), json!(false)),
            ("n", json!("n"), json!(false)),
            ("N", json!("N"), json!(false)),
            ("off", json!("off"), json!(false)),
            ("Off", json!("Off"), json!(false)),
            ("OFF", json!("OFF"), json!(false)),
            // YAML 1.2 booleans already agree; normalization is a no-op.
            ("true", json!(true), json!(true)),
            ("TRUE", json!(true), json!(true)),
            ("false", json!(false), json!(false)),
            ("TrUe", json!("TrUe"), json!("TrUe")),
            ("y2", json!("y2"), json!("y2")),
            // Underscore and base-0 integers (Go strips all underscores).
            ("1_000", json!("1_000"), json!(1000)),
            ("0x_1F", json!("0x_1F"), json!(31)),
            ("1__0", json!("1__0"), json!(10)),
            ("-_5", json!("-_5"), json!(-5)),
            ("_1", json!("_1"), json!("_1")), // hint gate: '_' never resolves
            // Legacy octal; invalid octal digits fall through to float.
            ("010", json!("010"), json!(8)),
            ("0777", json!("0777"), json!(511)),
            ("-010", json!("-010"), json!(-8)),
            ("+010", json!("+010"), json!(8)),
            ("08", json!("08"), json!(8)),
            ("00", json!("00"), json!(0)),
            ("-0", json!(0), json!(0)), // 0.9 parses -0 as integer 0
            // Prefix casing: Go base-0 accepts 0X/0O/0B, serde_yaml only 0x/0o/0b.
            ("0X1F", json!("0X1F"), json!(31)),
            ("0O17", json!("0O17"), json!(15)),
            ("0B101", json!("0B101"), json!(5)),
            ("0x1F", json!(31), json!(31)), // both parsers agree here
            ("0o17", json!(15), json!(15)),
            ("0b101", json!(5), json!(5)),
            ("-0x1F", json!(-31), json!(-31)),
            ("+0x1f", json!(31), json!(31)),
            // Trailing-dot mantissas: Rust's f64::from_str also accepts these
            // (`12.`->12.0), so they arrive as floats; only Go's integer
            // rendering of integral floats needs restoring.
            ("12.", json!(12.0), json!(12)),
            ("5.", json!(5.0), json!(5)),
            ("-12.", json!(-12.0), json!(-12)),
            ("+12.", json!(12.0), json!(12)),
            ("5.e2", json!(500.0), json!(500)),
            // Underscore floats: YAML 1.1 only, arrive as strings.
            (".5_0", json!(".5_0"), json!(0.5)),
            ("1.5_0", json!("1.5_0"), json!(1.5)),
            // Integral floats are canonicalized like json.Marshal.
            ("1e3", json!(1000.0), json!(1000)),
            ("1E3", json!(1000.0), json!(1000)),
            (".5", json!(0.5), json!(0.5)),
            (".5e2", json!(50.0), json!(50)),
            ("+.5", json!(0.5), json!(0.5)),
            ("-.5", json!(-0.5), json!(-0.5)),
            // Timestamps stay strings (yaml.v2 interface{} decode keeps them).
            ("2022-01-01", json!("2022-01-01"), json!("2022-01-01")),
            ("2022-1-2", json!("2022-1-2"), json!("2022-1-2")),
            ("2022-13-01", json!("2022-13-01"), json!("2022-13-01")),
            (
                "2022-01-01T10:30:00Z",
                json!("2022-01-01T10:30:00Z"),
                json!("2022-01-01T10:30:00Z"),
            ),
            ("20220101", json!(20220101), json!(20220101)),
            // Sexagesimal: yaml.v2 "purposefully unsupported" - strings.
            ("190:20:30", json!("190:20:30"), json!("190:20:30")),
            ("190:20:30.15", json!("190:20:30.15"), json!("190:20:30.15")),
            ("12:30", json!("12:30"), json!("12:30")),
            // Non-scalar-looking and overflow forms stay strings.
            ("1e", json!("1e"), json!("1e")),
            ("1.2.3", json!("1.2.3"), json!("1.2.3")),
            ("e5", json!("e5"), json!("e5")),
            ("inf", json!("inf"), json!("inf")),
            ("NaN", json!("NaN"), json!("NaN")),
            ("Infinity", json!("Infinity"), json!("Infinity")),
            ("nUll", json!("nUll"), json!("nUll")),
            ("1e400", json!("1e400"), json!("1e400")), // Go ParseFloat err != nil
            ("0x", json!("0x"), json!("0x")),
            // u64 agree in both parsers.
            (
                "18446744073709551615",
                json!(18446744073709551615u64),
                json!(18446744073709551615u64),
            ),
        ];
        for (scalar, input, expected) in cases {
            let mut value = input.clone();
            normalize_yaml_scalars(&mut value);
            assert_eq!(&value, expected, "plain scalar {scalar:?}");
            // Idempotence for every case.
            normalize_yaml_scalars(&mut value);
            assert_eq!(&value, expected, "second pass on {scalar:?}");
        }
    }

    /// Scalars that serde_yaml 0.9 can resolve as plain (YAML 1.2 forms)
    /// arrive as strings only when they were quoted in the YAML source; Go
    /// keeps those strings, so they must be preserved. This is the
    /// "quoted-number preservation" rule.
    #[test]
    fn preserves_quoted_yaml_12_scalars() {
        let cases: &[(&str, Value)] = &[
            // ("yaml quoted scalar", Go golden) - all remain strings.
            ("\"true\"", json!("true")),
            ("\"TRUE\"", json!("TRUE")),
            ("\"8080\"", json!("8080")),
            ("\"0x1F\"", json!("0x1F")),
            ("\"-0x1F\"", json!("-0x1F")),
            ("\"+0x1f\"", json!("+0x1f")),
            ("\"0o17\"", json!("0o17")),
            ("\"0b101\"", json!("0b101")),
            ("\"1e3\"", json!("1e3")),
            ("\".5\"", json!(".5")),
            ("\"12.\"", json!("12.")),
            ("\"5.e2\"", json!("5.e2")),
            ("\".inf\"", json!(".inf")),
            ("\".nan\"", json!(".nan")),
            ("\"-.inf\"", json!("-.inf")),
            ("\"-0\"", json!("-0")),
            ("\"+5\"", json!("+5")),
            ("\"18446744073709551615\"", json!("18446744073709551615")),
            ("\"2022-01-01\"", json!("2022-01-01")),
            ("\"null\"", json!("null")),
            ("\"~\"", json!("~")),
            ("\"\"", json!("")),
            // u128-range ints: plain form fails serde_json::Value parsing, so
            // a string can only be quoted; Go also keeps the quoted string.
            ("\"99999999999999999999\"", json!("99999999999999999999")),
        ];
        for (yaml, expected) in cases {
            let scalar = yaml.trim_matches('"');
            let mut value = Value::String(scalar.to_owned());
            normalize_yaml_scalars(&mut value);
            assert_eq!(&value, expected, "quoted scalar {yaml}");
        }
    }

    /// Documented, unavoidable deviation: after parsing to
    /// `serde_json::Value` the quote style of YAML-1.1-only scalars is lost,
    /// so an explicitly quoted `yes`/`1_000`/`010` is normalized exactly like
    /// the plain form. Everything else (see the preservation test) is safe.
    #[test]
    fn documents_quoted_yaml_11_only_deviation() {
        let cases: &[(&str, Value)] = &[
            ("yes", json!(true)),
            ("no", json!(false)),
            ("y", json!(true)),
            ("off", json!(false)),
            ("1_000", json!(1000)),
            ("010", json!(8)),
            ("0X1F", json!(31)),
            (".5_0", json!(0.5)),
        ];
        for (scalar, expected) in cases {
            let mut value = Value::String((*scalar).to_owned());
            normalize_yaml_scalars(&mut value);
            assert_eq!(&value, expected, "known deviation for quoted {scalar:?}");
        }
    }

    /// Round trip of a sample Xray YAML config: serde_yaml 0.9 output
    /// (constructed per its documented resolution, quoted scalars stay
    /// strings, `no` stays a string, numbers/bools resolve) through
    /// normalization equals the JSON produced by the Go reference
    /// (`serial.DecodeYAMLConfig` path), verified by running the pinned
    /// ghodss/yaml commit on the same document.
    #[test]
    fn round_trips_sample_config_to_go_equivalent_json() {
        // YAML source (Go probe input):
        //   log: info
        //   inbounds:
        //   - listen: 0.0.0.0
        //     port: 1080
        //     protocol: socks
        //     settings:
        //       udp: true
        //       auth: no
        //   streamSettings:
        //     network: tcp
        //     security: tls
        //     tlsSettings:
        //       allowInsecure: false
        //       alpn: [h2, http/1.1]
        //   outbounds:
        //   - protocol: vmess
        //     settings:
        //       vnext:
        //       - address: example.com
        //         port: 443
        //         users:
        //         - id: b831381d-6324-4d53-ad4f-8cda48b30811
        //           alterId: 0
        //           security: auto
        // serde_yaml 0.9 output: `no` is a string (YAML 1.2), `true`/`false`
        // are bools, ports are integers, everything else strings.
        let post_serde_yaml = json!({
            "log": "info",
            "inbounds": [{
                "listen": "0.0.0.0",
                "port": 1080,
                "protocol": "socks",
                "settings": {"udp": true, "auth": "no"}
            }],
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"allowInsecure": false, "alpn": ["h2", "http/1.1"]}
            },
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "example.com",
                    "port": 443,
                    "users": [{
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "alterId": 0,
                        "security": "auto"
                    }]
                }]}
            }]
        });
        // Golden: output of the Go probe running ghodss/yaml
        // v1.0.1-0.20220118164431-d8423dcdf344 YAMLToJSON on the document.
        let go_golden = json!({
            "inbounds": [{
                "listen": "0.0.0.0",
                "port": 1080,
                "protocol": "socks",
                "settings": {"auth": false, "udp": true}
            }],
            "log": "info",
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{
                    "address": "example.com",
                    "port": 443,
                    "users": [{
                        "alterId": 0,
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                        "security": "auto"
                    }]
                }]}
            }],
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"allowInsecure": false, "alpn": ["h2", "http/1.1"]}
            }
        });
        let mut value = post_serde_yaml;
        normalize_yaml_scalars(&mut value);
        assert_eq!(value, go_golden);
        // Idempotent.
        normalize_yaml_scalars(&mut value);
        assert_eq!(value, go_golden);
    }

    /// Nested structures normalize at every depth, keys are untouched, and
    /// integral f64 numbers (Go marshals `1000`, not `1000.0`) are
    /// canonicalized.
    #[test]
    fn normalizes_nested_values_and_canonicalizes_integral_floats() {
        let mut value = json!({
            "inbounds": [{"settings": {"auth": "no", "level": "1_0"}}],
            "float": 1000.0,
            "frac": 1.5,
            "huge": 1e22,
            "name": "yes", // keys are never rewritten; this is a value
            "ok": true,
            "none": null
        });
        normalize_yaml_scalars(&mut value);
        assert_eq!(value["inbounds"][0]["settings"]["auth"], json!(false));
        assert_eq!(value["inbounds"][0]["settings"]["level"], json!(10));
        assert_eq!(value["float"], json!(1000));
        assert!(value["float"].is_u64());
        assert_eq!(value["frac"], json!(1.5));
        assert!(value["frac"].is_f64());
        assert_eq!(value["huge"], json!(1e22));
        assert!(value["huge"].is_f64()); // beyond u64: stays a float
        assert_eq!(value["name"], json!(true));
        assert_eq!(value["ok"], json!(true));
        assert!(value["none"].is_null());
    }

    /// serde_yaml 0.9 scalar model sanity (drives the preservation gate).
    #[test]
    fn serde_yaml09_model_matches_documented_resolution() {
        for seen in [
            "null",
            "Null",
            "NULL",
            "~",
            "",
            "true",
            "TRUE",
            "False",
            "5",
            "+5",
            "-5",
            "-0",
            "0",
            "0x1F",
            "0o17",
            "0b101",
            "-0x1F",
            "1e3",
            "1E3",
            ".5",
            ".5e2",
            "+.5",
            "-.5",
            "12.",
            "5.e2",
            ".inf",
            ".nan",
            "-.inf",
            "8080",
            "18446744073709551615",
            "99999999999999999999",
        ] {
            assert!(
                serde_yaml09_sees_scalar(seen),
                "0.9 should resolve {seen:?}"
            );
        }
        for unseen in [
            "yes",
            "y",
            "no",
            "n",
            "on",
            "off",
            "On",
            "OFF",
            "TrUe",
            "y2",
            "1_000",
            "010",
            "00",
            "08",
            "-010",
            "0X1F",
            "0B101",
            "0O17",
            ".5_0",
            "1.5_0",
            "1e",
            "1.2.3",
            "e5",
            "inf",
            "NaN",
            "Infinity",
            "nUll",
            "2022-01-01",
            "190:20:30",
            "0x",
            "_1",
            "1e400",
        ] {
            assert!(
                !serde_yaml09_sees_scalar(unseen),
                "0.9 should not resolve {unseen:?}"
            );
        }
    }

    /// Go applies the root `"env"` map (`infra/conf/xray.go` Config.Build ->
    /// os.Setenv) and performs no `${VAR}` expansion anywhere, so env strings
    /// and `${...}` text pass through untouched.
    #[test]
    fn apply_env_consumes_valid_root_env_and_never_expands() {
        let mut value = json!({
            "env": {
                "XRAY_TEST_CONFIG_ENV": "configured",
                "XRAY_TEST_CONFIG_EMPTY": null, // Go decodes null as ""
                "XRAY_LOCATION_ASSET": "/custom/path"
            },
            "log": {"loglevel": "${XRAY_TEST_CONFIG_ENV}"},
            "inbounds": [{"protocol": "${UNSET_VAR}", "extra": "${VAR:-default}"}]
        });
        // Lookup behaves like an environment: one var set, the rest unset.
        // Go's behavior for unset variables is "no expansion happens at all".
        let lookup = |name: &str| match name {
            "XRAY_TEST_CONFIG_ENV" => Some("before".to_owned()),
            _ => None,
        };
        apply_env(&mut value, &lookup);
        // The env section is consumed ...
        assert!(value.get("env").is_none());
        // ... nothing else is rewritten (no ${} syntax exists in Go).
        assert_eq!(value["log"]["loglevel"], json!("${XRAY_TEST_CONFIG_ENV}"));
        assert_eq!(value["inbounds"][0]["protocol"], json!("${UNSET_VAR}"));
        assert_eq!(value["inbounds"][0]["extra"], json!("${VAR:-default}"));
        // Idempotent.
        apply_env(&mut value, &lookup);
        assert!(value.get("env").is_none());
    }

    /// Go rejects configs whose env values are not strings
    /// ("json: cannot unmarshal number into ... of type string"); leaving the
    /// invalid section in place reproduces the rejection downstream.
    #[test]
    fn apply_env_rejects_non_string_env_values_like_go() {
        for bad in [
            json!({"env": {"A": 1}}),
            json!({"env": {"A": true}}),
            json!({"env": [1]}),
            json!({"env": "x"}),
        ] {
            let mut value = json!({"env": bad["env"].clone(), "log": {"loglevel": "info"}});
            apply_env(&mut value, &|_| None);
            assert!(
                value.get("env").is_some(),
                "invalid env must stay for rejection: {bad}"
            );
            assert_eq!(
                value["log"]["loglevel"],
                json!("info"),
                "rest untouched: {bad}"
            );
        }
        // Null (nil map in Go) and empty objects are valid and consumed.
        for valid in [json!(null), json!({})] {
            let mut value = json!({"env": valid.clone(), "log": {"loglevel": "info"}});
            apply_env(&mut value, &|_| None);
            assert!(value.get("env").is_none(), "valid env consumed: {valid}");
        }
    }

    /// Only the *root* `env` object is Go's `EnvConfig`; nested `env` keys are
    /// ordinary settings and must be left alone, and non-object roots are
    /// ignored without panicking.
    #[test]
    fn apply_env_only_consumes_root_env() {
        let mut value = json!({
            "inbounds": [{"protocol": "socks", "settings": {"env": {"A": "nested"}}}]
        });
        apply_env(&mut value, &|_| None);
        assert_eq!(
            value["inbounds"][0]["settings"]["env"]["A"],
            json!("nested"),
            "nested env objects are plain settings"
        );

        let mut array = json!([{"env": {"A": "x"}}]);
        apply_env(&mut array, &|_| None);
        assert_eq!(array[0]["env"]["A"], json!("x"));

        let mut scalar = json!("env");
        apply_env(&mut scalar, &|_| None);
        assert_eq!(scalar, json!("env"));
    }
}
