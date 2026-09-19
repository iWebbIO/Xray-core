//! VMess AEAD authentication and buffer-oriented protocol codecs.
//!
//! The server authenticator owns both AuthID replay protection and the
//! three-minute `(user, body key, body IV)` history used by the Go implementation.
//! Keep one authenticator per inbound, shared behind a lock across connections;
//! constructing one per connection defeats replay protection. Socket dispatch,
//! transport selection, and multiplexing belong to the runtime.

pub mod crypto;
pub mod encoding;
pub mod stream;

use std::{collections::HashMap, fmt};

use anyhow::{Context, Result, ensure};
use rand::RngCore;
use zeroize::Zeroize;

pub use encoding::{
    BodyDecoder, BodyEncoder, BodyFrame, BodyKeys, Command, RequestHeader, ResponseHeader, Security,
};

const SESSION_HISTORY_SECONDS: i64 = 180;

/// A VMess user. Debug output deliberately omits credential material.
#[derive(Clone)]
pub struct Account {
    id: [u8; 16],
    command_key: [u8; 16],
    email: String,
}

impl Account {
    pub fn new(id: [u8; 16], email: impl Into<String>) -> Self {
        Self {
            command_key: crypto::command_key(&id),
            id,
            email: email.into(),
        }
    }

    pub fn from_user_id(id: &str, email: impl Into<String>) -> Result<Self> {
        Ok(Self::new(*crate::user::parse_id(id)?.as_bytes(), email))
    }

    pub fn email(&self) -> &str {
        &self.email
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Account")
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        self.id.zeroize();
        self.command_key.zeroize();
    }
}

/// Result of an authenticated request. The consumed count excludes body bytes
/// that may already follow the encrypted header in the input buffer.
pub struct AuthenticatedRequest {
    pub account_index: usize,
    pub header: RequestHeader,
    pub consumed: usize,
}

/// Shared inbound state. Capacity exhaustion fails closed: unexpired replay
/// entries are never evicted to make room for a new connection.
pub struct ServerAuthenticator {
    accounts: Vec<Account>,
    auth_ids: crypto::AuthIdReplayCache,
    sessions: HashMap<[u8; 48], i64>,
    max_sessions: usize,
}

impl ServerAuthenticator {
    pub fn new(accounts: Vec<Account>, max_sessions: usize) -> Result<Self> {
        ensure!(!accounts.is_empty(), "VMess requires at least one account");
        ensure!(max_sessions != 0, "VMess replay capacity must be nonzero");
        Ok(Self {
            accounts,
            auth_ids: crypto::AuthIdReplayCache::new(max_sessions),
            sessions: HashMap::new(),
            max_sessions,
        })
    }

    pub fn account(&self, index: usize) -> Option<&Account> {
        self.accounts.get(index)
    }

    /// Authenticate the fixed 42-byte request prefix and return the total wire
    /// size. A socket owner can read that prefix, call this method under a short
    /// lock, read the remaining bytes without the lock, then call `open_request`.
    /// This method does not reserve either replay cache.
    pub fn request_wire_len(&self, prefix: &[u8], now: i64) -> Result<usize> {
        ensure!(
            prefix.len() >= crypto::REQUEST_HEADER_PREFIX_LEN,
            "truncated VMess encrypted request prefix"
        );
        let (account_index, auth_id, _) = self.identify_account(prefix, now)?;
        let encrypted_length = prefix[16..34].try_into().expect("fixed encrypted length");
        let nonce = prefix[34..42].try_into().expect("fixed connection nonce");
        let length = crypto::open_request_header_length(
            &self.accounts[account_index].command_key,
            &auth_id,
            encrypted_length,
            nonce,
        )
        .context("authenticate VMess header length")?;
        Ok(crypto::REQUEST_HEADER_PREFIX_LEN + length + crypto::AEAD_TAG_LEN)
    }

    fn identify_account(&self, wire: &[u8], now: i64) -> Result<(usize, [u8; 16], crypto::AuthId)> {
        let auth_id: [u8; 16] = wire
            .get(..16)
            .context("truncated VMess AuthID")?
            .try_into()
            .expect("AuthID slice has fixed length");
        self.accounts
            .iter()
            .enumerate()
            .find_map(|(index, account)| {
                crypto::validate_auth_id(&account.command_key, &auth_id, now)
                    .ok()
                    .map(|auth| (index, auth_id, auth))
            })
            .context("invalid VMess user or expired AuthID")
    }

    /// Authenticate one complete encrypted header. `now` is Unix time in seconds.
    /// Incomplete or invalid input does not reserve an AuthID or body session.
    /// The caller must retain the same input while collecting an incomplete frame.
    pub fn open_request(&mut self, wire: &[u8], now: i64) -> Result<AuthenticatedRequest> {
        let (account_index, auth_id, auth) = self.identify_account(wire, now)?;
        let account = &self.accounts[account_index];
        let (plaintext, consumed) = crypto::open_request_header(&account.command_key, wire)
            .context("authenticate VMess request header")?;
        let (header, plaintext_consumed) =
            RequestHeader::decode(&plaintext).context("decode VMess request header")?;
        ensure!(
            plaintext_consumed == plaintext.len(),
            "unexpected trailing bytes in VMess request header"
        );

        let mut session = [0; 48];
        session[..16].copy_from_slice(&account.id);
        session[16..32].copy_from_slice(&header.body_key);
        session[32..].copy_from_slice(&header.body_iv);
        self.sessions
            .retain(|_, inserted| now.saturating_sub(*inserted) < SESSION_HISTORY_SECONDS);
        ensure!(
            !self.sessions.contains_key(&session),
            "replayed VMess body session"
        );
        ensure!(
            self.sessions.len() < self.max_sessions,
            "VMess session replay cache is full"
        );
        self.auth_ids
            .check_and_insert(auth_id, auth.timestamp, now)
            .context("VMess AuthID replay check")?;
        self.sessions.insert(session, now);
        Ok(AuthenticatedRequest {
            account_index,
            header,
            consumed,
        })
    }
}

/// Seal a request using a fresh AuthID random value and connection nonce.
/// Callers must also choose a fresh `body_key` and `body_iv` for each session;
/// reusing the same body key/IV pair across connections is rejected by the server.
pub fn seal_request(account: &Account, header: &RequestHeader, now: i64) -> Result<Vec<u8>> {
    ensure!(now >= 0, "VMess timestamps must be nonnegative");
    let plaintext = header.encode().context("encode VMess request header")?;
    let mut random = [0; 4];
    let mut nonce = [0; 8];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut random)
        .context("generate VMess AuthID entropy")?;
    rng.try_fill_bytes(&mut nonce)
        .context("generate VMess connection nonce")?;
    let auth_id = crypto::create_auth_id(&account.command_key, now, random);
    crypto::seal_request_header(&account.command_key, &plaintext, &auth_id, &nonce)
        .context("seal VMess request header")
}

/// Encrypt a response header with the direction-specific keys derived from the
/// request. The authentication byte must match the request's response token.
pub fn seal_response(request: &RequestHeader, response: &ResponseHeader) -> Result<Vec<u8>> {
    ensure!(
        response.response_auth == request.response_auth,
        "VMess response authentication byte differs from request"
    );
    let (key, iv) = crypto::derive_response_key_iv(&request.body_key, &request.body_iv);
    crypto::seal_response_header(&key, &iv, &response.encode()?)
        .context("seal VMess response header")
}

/// Authenticate one encrypted response header and return its exact wire length.
pub fn open_response(request: &RequestHeader, wire: &[u8]) -> Result<(ResponseHeader, usize)> {
    let (key, iv) = crypto::derive_response_key_iv(&request.body_key, &request.body_iv);
    let (plaintext, consumed) = crypto::open_response_header(&key, &iv, wire)
        .context("authenticate VMess response header")?;
    let (response, decoded) = ResponseHeader::decode(&plaintext, request.response_auth)
        .context("decode VMess response header")?;
    ensure!(
        decoded == plaintext.len(),
        "unexpected trailing bytes in VMess response header"
    );
    Ok((response, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Destination;

    const NOW: i64 = 1_700_000_000;

    fn account() -> Account {
        Account::new([0x11; 16], "user@example.test")
    }

    fn header() -> RequestHeader {
        RequestHeader {
            body_iv: [0x22; 16],
            body_key: [0x33; 16],
            response_auth: 0x44,
            options: 1,
            security: Security::Aes128Gcm,
            command: Command::Tcp,
            destination: Some(Destination::new("example.test", 443).unwrap()),
            padding: vec![0x55; 3],
        }
    }

    fn wire(account: &Account, header: &RequestHeader, now: i64, seed: u8) -> Vec<u8> {
        let auth_id = crypto::create_auth_id(&account.command_key, now, [seed; 4]);
        crypto::seal_request_header(
            &account.command_key,
            &header.encode().unwrap(),
            &auth_id,
            &[seed; 8],
        )
        .unwrap()
    }

    #[test]
    fn authentication_preserves_pipelined_body_and_user_identity() {
        let account = account();
        let mut wire = wire(&account, &header(), NOW, 1);
        let header_size = wire.len();
        wire.extend_from_slice(b"pipelined encrypted body");
        let mut auth =
            ServerAuthenticator::new(vec![Account::new([0x77; 16], "another"), account], 16)
                .unwrap();
        let request = auth.open_request(&wire, NOW).unwrap();
        assert_eq!(request.account_index, 1);
        assert_eq!(auth.account(1).unwrap().email(), "user@example.test");
        assert_eq!(request.header.destination, header().destination);
        assert_eq!(request.consumed, header_size);
        assert_eq!(&wire[request.consumed..], b"pipelined encrypted body");
    }

    #[test]
    fn length_prefix_authentication_does_not_reserve_the_session() {
        let account = account();
        let wire = wire(&account, &header(), NOW, 1);
        let mut auth = ServerAuthenticator::new(vec![account], 1).unwrap();
        for count in 0..crypto::REQUEST_HEADER_PREFIX_LEN {
            assert!(auth.request_wire_len(&wire[..count], NOW).is_err());
        }
        let prefix = &wire[..crypto::REQUEST_HEADER_PREFIX_LEN];
        assert_eq!(auth.request_wire_len(prefix, NOW).unwrap(), wire.len());
        assert_eq!(auth.request_wire_len(prefix, NOW).unwrap(), wire.len());
        let mut damaged = prefix.to_vec();
        damaged[20] ^= 1;
        assert!(auth.request_wire_len(&damaged, NOW).is_err());
        auth.open_request(&wire, NOW).unwrap();
    }

    #[test]
    fn replay_checks_cover_auth_ids_and_fresh_auth_ids_for_reused_sessions() {
        let account = account();
        let first = wire(&account, &header(), NOW, 1);
        let second = wire(&account, &header(), NOW, 2);
        let mut auth = ServerAuthenticator::new(vec![account], 16).unwrap();
        auth.open_request(&first, NOW).unwrap();
        assert!(auth.open_request(&first, NOW).is_err());
        assert!(auth.open_request(&second, NOW).is_err());
    }

    #[test]
    fn incomplete_and_tampered_requests_do_not_poison_replay_state() {
        let account = account();
        let wire = wire(&account, &header(), NOW, 1);
        let mut auth = ServerAuthenticator::new(vec![account], 16).unwrap();
        for count in 0..wire.len() {
            assert!(auth.open_request(&wire[..count], NOW).is_err());
        }
        let mut damaged = wire.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(auth.open_request(&damaged, NOW).is_err());
        auth.open_request(&wire, NOW).unwrap();
    }

    #[test]
    fn authenticated_invalid_plaintext_does_not_poison_replay_state() {
        let account = account();
        let auth_id = crypto::create_auth_id(&account.command_key, NOW, [1; 4]);
        let invalid = crypto::seal_request_header(
            &account.command_key,
            b"not a VMess request",
            &auth_id,
            &[1; 8],
        )
        .unwrap();
        let valid = wire(&account, &header(), NOW, 1);
        let mut auth = ServerAuthenticator::new(vec![account], 16).unwrap();
        assert!(auth.open_request(&invalid, NOW).is_err());
        auth.open_request(&valid, NOW).unwrap();
    }

    #[test]
    fn session_history_expires_at_three_minutes_and_remains_bounded() {
        let account = account();
        let first = wire(&account, &header(), NOW, 1);
        let replay = wire(&account, &header(), NOW + 179, 2);
        let expired = wire(&account, &header(), NOW + 180, 3);
        let mut different_header = header();
        different_header.body_key[0] ^= 1;
        let distinct = wire(&account, &different_header, NOW + 121, 4);
        let mut auth = ServerAuthenticator::new(vec![account], 1).unwrap();
        auth.open_request(&first, NOW).unwrap();
        assert!(auth.open_request(&distinct, NOW + 121).is_err());
        assert!(auth.open_request(&replay, NOW + 179).is_err());
        auth.open_request(&expired, NOW + 180).unwrap();
    }

    #[test]
    fn account_credentials_are_redacted_and_invalid_configuration_is_rejected() {
        let account = account();
        let debug = format!("{account:?}");
        assert!(!debug.contains("command_key"));
        assert!(!debug.contains("17, 17"));
        assert!(ServerAuthenticator::new(vec![], 1).is_err());
        assert!(ServerAuthenticator::new(vec![account.clone()], 0).is_err());
        assert!(seal_request(&account, &header(), -1).is_err());
    }

    #[test]
    fn response_checks_authentication_and_preserves_body() {
        let request = header();
        let response = ResponseHeader {
            response_auth: request.response_auth,
            options: 0,
            command: None,
        };
        let mut wire = seal_response(&request, &response).unwrap();
        let header_size = wire.len();
        for count in 0..wire.len() {
            assert!(open_response(&request, &wire[..count]).is_err());
        }
        wire.extend_from_slice(b"response body");
        let (decoded, consumed) = open_response(&request, &wire).unwrap();
        assert_eq!(decoded, response);
        assert_eq!(consumed, header_size);
        assert_eq!(&wire[consumed..], b"response body");
        let mut wrong_request = request.clone();
        wrong_request.response_auth ^= 1;
        assert!(open_response(&wrong_request, &wire).is_err());
        assert!(seal_response(&wrong_request, &response).is_err());
    }
}
