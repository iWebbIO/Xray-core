//! Native VLESS encryption and Vision building blocks.
//!
//! The [`handshake`] module establishes native 1-RTT hybrid encrypted sessions
//! with configured NFS relay keys. The inner VLESS request must still authenticate
//! the account. Vision primitives do not switch an outer TLS connection to direct
//! socket I/O. See `rust/notes/VLESS_SECURITY.md` and `rust/notes/VLESS_HANDSHAKE.md`
//! for the remaining runtime and protocol limitations.

mod derive;
pub mod encryption;
pub mod handshake;
pub mod vision;

pub use derive::derive_key;
