//! Object names constitute XDRIVE's compatible wire format.

use rand::{RngCore, rngs::OsRng};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SESSIONS_DIR: &str = "sessions";
pub const STREAMS_DIR: &str = "streams";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Segment,
    End,
    Error,
}
impl ObjectKind {
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Segment => ".seg",
            Self::End => ".end",
            Self::Error => ".err",
        }
    }
}

pub fn object_name(prefix: &str, sequence: u64, kind: ObjectKind) -> io::Result<String> {
    if sequence > i64::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XDRIVE sequence exceeds signed 64-bit wire range",
        ));
    }
    Ok(format!("{prefix}/{sequence:09}{}", kind.suffix()))
}

pub fn parse_entry(name: &str) -> Option<(u64, ObjectKind)> {
    let (number, suffix) = name.rsplit_once('.')?;
    let kind = match suffix {
        "seg" => ObjectKind::Segment,
        "end" => ObjectKind::End,
        "err" => ObjectKind::Error,
        _ => return None,
    };
    let sequence: i64 = number.parse().ok()?;
    (sequence >= 0).then_some((sequence as u64, kind))
}

pub fn new_session_id() -> io::Result<String> {
    let mut random = [0; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(io::Error::other)?;
    let mut result = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("writing to a string is infallible");
    }
    Ok(result)
}

pub fn validate_session_id(session: &str) -> io::Result<()> {
    if session.is_empty()
        || session.len() > 255
        || matches!(session, "." | "..")
        || session
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\' | b':' | 0))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid XDRIVE session identifier",
        ));
    }
    Ok(())
}

pub fn announcement_name(session: &str, at: SystemTime) -> io::Result<String> {
    validate_session_id(session)?;
    let nanos = at
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let nanos = i64::try_from(nanos).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "XDRIVE timestamp exceeds signed 64-bit nanoseconds",
        )
    })?;
    Ok(format!("{SESSIONS_DIR}/{nanos}-{session}"))
}

pub fn parse_announcement(name: &str) -> Option<(String, SystemTime)> {
    let (session, nanos) = parse_announcement_nanos(name)?;
    Some((
        session,
        UNIX_EPOCH.checked_add(std::time::Duration::from_nanos(nanos as u64))?,
    ))
}

/// Parse the full nanosecond wire timestamp without platform SystemTime
/// rounding (Windows SystemTime has 100 ns resolution).
pub fn parse_announcement_nanos(name: &str) -> Option<(String, i64)> {
    let (nanos, session) = name.split_once('-')?;
    if nanos.is_empty() || validate_session_id(session).is_err() {
        return None;
    }
    let nanos: i64 = nanos.parse().ok()?;
    if nanos < 0 {
        return None;
    }
    Some((session.to_owned(), nanos))
}

pub fn session_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}")
}
pub fn uplink_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}/c2s")
}
pub fn downlink_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}/s2c")
}

/// Google Drive/template backends flatten path components with this separator.
pub fn flatten(name: &str) -> String {
    name.replace('/', "~")
}
