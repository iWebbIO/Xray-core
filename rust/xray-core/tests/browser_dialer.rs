//! Integration checks for the browser dialer's public surface
//! (`transport/internet/browser_dialer` in Go).
//!
//! The workspace forbids `unsafe`, so edition-2024's `unsafe
//! std::env::set_var` cannot arm the dialer from a test binary; the armed
//! lifecycle (page serving, CSRF token, WebSocket relay, reload restart) is
//! therefore covered by the in-crate unit tests. What is deterministic
//! without touching the environment is verified here: the `platform`
//! env-flag semantics of `address()`, and the unarmed surface of
//! `reload`, `has_browser`, and the named `dial` rejection.

use tokio_util::sync::CancellationToken;
use xray_core::transport::browser_dialer::{address, dial, has_browser, reload};

#[tokio::test]
async fn address_matches_go_platform_env_flag_semantics() {
    // Go's platform.NewEnvFlag(BrowserDialerAddress).GetValue: the primary
    // "xray.browser.dialer" name wins (a set-but-empty value disarms, exactly
    // like Go returning ""), then the normalized "XRAY_BROWSER_DIALER",
    // then nothing.
    let primary = std::env::var("xray.browser.dialer").ok();
    let alternate = std::env::var("XRAY_BROWSER_DIALER").ok();
    let expected = primary
        .or(alternate)
        .and_then(|value| (!value.is_empty()).then_some(value));
    assert_eq!(address(), expected);
}

#[tokio::test]
async fn unarmed_reload_is_idempotent_and_dial_rejects_without_a_browser() {
    if address().is_some() {
        // The ambient environment arms the dialer; nothing deterministic
        // can be asserted without binding that address.
        return;
    }
    let cancel = CancellationToken::new();
    reload(cancel.clone())
        .await
        .expect("unarmed reload succeeds");
    // Go's Reload returns immediately when the address is unchanged.
    reload(cancel.clone())
        .await
        .expect("same-address reload is idempotent");
    assert!(!has_browser());

    let error = dial("ws://example.test/echo")
        .await
        .err()
        .expect("no browser is connected");
    assert!(
        error.to_string().contains("no browser"),
        "unexpected error: {error}"
    );

    cancel.cancel();
    assert!(!has_browser());
    let error = dial("ws://example.test/echo")
        .await
        .err()
        .expect("dial stays rejected after cancel");
    assert!(
        error.to_string().contains("no browser"),
        "unexpected error: {error}"
    );
}
