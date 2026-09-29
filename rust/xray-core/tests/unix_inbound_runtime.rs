//! The unix domain socket inbound through the real config/runtime surface: a
//! path `listen` on a dokodemo inbound binds the unix listener (unix builds)
//! or fails startup with the named platform rejection (Windows); any other
//! inbound with a path listen fails by name at config validation.

use std::time::Duration;

use serde_json::json;
use tokio::time::timeout;
use xray_core::{Config, Server};

const ENVELOPE: Duration = Duration::from_secs(10);

fn unix_dokodemo(listen: &str) -> Config {
    Config::from_json(
        &json!({
            "inbounds": [{
                "listen": listen, "port": 0, "tag": "unix-in",
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1", "port": 9, "network": "unix"}
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}]
        })
        .to_string(),
    )
    .unwrap()
}

#[tokio::test]
async fn unix_listen_reaches_the_listener_or_names_its_platform() {
    timeout(ENVELOPE, async {
        let config = unix_dokodemo("/tmp/xray-unix-inbound-test.sock");
        config
            .validate()
            .expect("the config surface accepts the path");
        let started = Server::start(config).await;
        match started {
            Ok(server) => {
                // A unix build: the listener bound. (Prove the socket file
                // exists, then shut down cleanly.)
                #[cfg(unix)]
                assert!(
                    std::path::Path::new("/tmp/xray-unix-inbound-test.sock").exists(),
                    "the unix socket file must exist"
                );
                server.shutdown().await.unwrap();
            }
            Err(error) => {
                // This platform build has no AF_UNIX listeners: the named
                // rejection, never a silent TCP fallback.
                let message = format!("{error:#}");
                assert!(
                    message.contains("Unix build"),
                    "the platform rejection must name itself: {message}"
                );
            }
        }
    })
    .await
    .expect("the unix inbound runtime test timed out");
}

#[tokio::test]
async fn a_path_listen_on_other_inbounds_fails_by_name() {
    let config = Config::from_json(
        &json!({
            "inbounds": [{
                "listen": "/tmp/xray-not-dokodemo.sock", "port": 0, "tag": "socks-unix",
                "protocol": "socks", "settings": {"auth": "noauth"}
            }],
            "outbounds": [{"protocol": "freedom"}]
        })
        .to_string(),
    )
    .unwrap();
    let error = config.validate().unwrap_err();
    assert!(
        format!("{error:#}").contains("dokodemo-door"),
        "the conflict must name the required inbound: {error:#}"
    );
}
