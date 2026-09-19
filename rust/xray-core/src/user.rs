use anyhow::{Context, Result, bail};
use uuid::Uuid;

/// Xray short user IDs use UUIDv5 with the all-zero namespace, not the DNS namespace.
pub fn parse_id(input: &str) -> Result<Uuid> {
    match input.len() {
        1..=30 => Ok(Uuid::new_v5(&Uuid::nil(), input.as_bytes())),
        32..=36 => {
            // The Go parser permits a hyphen before each group, including the first.
            let mut remaining = input;
            let mut compact = String::with_capacity(32);
            for length in [8, 4, 4, 4, 12] {
                remaining = remaining.strip_prefix('-').unwrap_or(remaining);
                let group = remaining.get(..length).context("invalid UUID")?;
                compact.push_str(group);
                remaining = &remaining[length..];
            }
            Ok(Uuid::parse_str(&compact).context("invalid UUID")?)
        }
        _ => bail!("user ID must be a UUID or contain 1..30 bytes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_reference_short_and_canonical_ids() {
        assert_eq!(
            parse_id("example").unwrap().to_string(),
            "feb54431-301b-52bb-a6dd-e1e93e81bb9e"
        );
        let id = "00112233-4455-6677-8899-aabbccddeeff";
        assert_eq!(
            parse_id(id).unwrap(),
            parse_id(&id.replace('-', "")).unwrap()
        );
        assert!(parse_id("").is_err());
        assert!(parse_id(&"a".repeat(31)).is_err());
        assert!(parse_id(&"é".repeat(16)).is_err());
    }
}
