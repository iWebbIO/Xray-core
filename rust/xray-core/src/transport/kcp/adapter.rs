//! Strict runtime configuration and destination dialing for the bare UDP engine.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Config, KcpStream, StreamOptions, connect};
use crate::{
    address::{Address, Destination},
    transport::BoxStream,
};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Settings {
    mtu: Option<u32>,
    tti: Option<u32>,
    uplink_capacity: Option<u32>,
    downlink_capacity: Option<u32>,
    cwnd_multiplier: Option<u32>,
    max_sending_window: Option<u32>,
    header: Option<Header>,
    seed: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    r#type: String,
}

/// Runtime cancellation must not leave the outbound UDP task in the public
/// stream's graceful-close linger. Normal I/O, flush and shutdown still forward
/// unchanged; only destruction requests immediate cancellation. Socket release
/// still requires the cancelled tasks to be scheduled by the Tokio runtime.
struct RuntimeStream {
    inner: KcpStream,
}

impl Drop for RuntimeStream {
    fn drop(&mut self) {
        self.inner.cancel();
    }
}

impl AsyncRead for RuntimeStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for RuntimeStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Config {
    /// Accept the active Go `infra/conf/transport_method.go` KCP settings.
    /// `maxSendingWindow` is bytes; there is no read/write-buffer MiB conversion.
    /// Legacy `congestion`, `readBufferSize`, and `writeBufferSize` are rejected,
    /// because the current Go Config no longer implements those settings.
    pub fn from_json(value: &Value) -> Result<Self> {
        let settings: Settings =
            serde_json::from_value(value.clone()).context("invalid KCP settings")?;
        ensure!(
            settings.seed.is_none(),
            "legacy KCP seed obfuscation is not supported"
        );
        if let Some(header) = settings.header {
            ensure!(
                header.r#type == "none",
                "legacy KCP header {:?} is not supported",
                header.r#type
            );
        }
        let mut config = Self::default();
        if let Some(value) = settings.mtu {
            config.mtu = value as usize;
        }
        if let Some(value) = settings.tti {
            config.tti_ms = value;
        }
        if let Some(value) = settings.uplink_capacity {
            config.uplink_capacity = value;
        }
        if let Some(value) = settings.downlink_capacity {
            config.downlink_capacity = value;
        }
        if let Some(value) = settings.cwnd_multiplier {
            config.cwnd_multiplier = value;
        }
        if let Some(value) = settings.max_sending_window {
            config.max_sending_window = value as usize;
        }
        ensure!(
            config.tti_ms >= 10,
            "KCP configured TTI must be 10..1000 milliseconds"
        );
        config.validate().context("unsupported KCP settings")?;
        Ok(config)
    }
}

/// Open UDP using the dispatcher-provided resolution when available. An empty
/// explicit address list is an error, never permission to consult system DNS.
/// UDP connect proves only local socket setup: fallback tries another address
/// only on socket errors, not on asynchronous reachability or application loss.
/// The runtime owns the overall DNS/dial/TLS deadline and outer TLS wrapping.
/// Dropping the returned stream cancels its UDP driver instead of lingering.
pub async fn connect_destination(
    destination: &Destination,
    resolved: Option<&[SocketAddr]>,
    config: Config,
) -> io::Result<(BoxStream, SocketAddr)> {
    const ADDRESS_LIMIT: usize = 64;
    config.validate()?;
    if destination.port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KCP destination port must be nonzero",
        ));
    }
    let addresses = if let Some(addresses) = resolved {
        if addresses.len() > ADDRESS_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many resolved KCP addresses (maximum 64)",
            ));
        }
        addresses.to_vec()
    } else {
        match &destination.address {
            Address::Ip(ip) => vec![SocketAddr::new(*ip, destination.port)],
            Address::Domain(host) => {
                let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), destination.port))
                    .await?
                    .take(ADDRESS_LIMIT + 1)
                    .collect();
                if addresses.len() > ADDRESS_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many resolved KCP addresses (maximum 64)",
                    ));
                }
                addresses
            }
        }
    };
    let mut last_error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "no resolved KCP destination addresses",
    );
    for address in addresses {
        if address.port() == 0 {
            last_error = io::Error::new(
                io::ErrorKind::InvalidInput,
                "resolved KCP destination port must be nonzero",
            );
            continue;
        }
        match connect(address, config.clone(), StreamOptions::default()).await {
            Ok(stream) => {
                let bound = stream.local_addr();
                return Ok((Box::new(RuntimeStream { inner: stream }), bound));
            }
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::super::KcpListener;
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn strict_json_preserves_go_defaults_and_active_field_units() {
        let defaults = Config::from_json(&json!({})).unwrap();
        assert_eq!(
            (
                defaults.mtu,
                defaults.tti_ms,
                defaults.uplink_capacity,
                defaults.downlink_capacity,
                defaults.cwnd_multiplier,
                defaults.max_sending_window
            ),
            (1350, 50, 5, 20, 1, 2 * 1024 * 1024)
        );
        let config=Config::from_json(&json!({"mtu":1200,"tti":10,"uplinkCapacity":3,"downlinkCapacity":9,"cwndMultiplier":2,"maxSendingWindow":65536,"header":{"type":"none"}})).unwrap();
        assert_eq!(
            (
                config.mtu,
                config.tti_ms,
                config.uplink_capacity,
                config.downlink_capacity,
                config.cwnd_multiplier,
                config.max_sending_window
            ),
            (1200, 10, 3, 9, 2, 65536)
        );
    }

    #[test]
    fn ignored_legacy_fields_and_unsupported_security_are_not_accepted() {
        for settings in [
            json!({"congestion":false}),
            json!({"congestion":true}),
            json!({"readBufferSize":2}),
            json!({"writeBufferSize":2}),
            json!({"seed":""}),
            json!({"seed":"secret"}),
            json!({"header":{"type":"srtp"}}),
            json!({"header":{"type":"none","unknown":1}}),
            json!({"header":{}}),
            json!({"unknown":1}),
            json!({"tti":1}),
            json!({"tti":1001}),
            json!({"mtu":21}),
            json!({"maxSendingWindow":1349}),
            json!({"cwndMultiplier":0}),
            json!({"cwndMultiplier":17}),
            json!({"uplinkCapacity":0}),
        ] {
            assert!(
                Config::from_json(&settings).is_err(),
                "unexpectedly accepted {settings}"
            );
        }
    }

    #[tokio::test]
    async fn explicit_resolution_is_used_without_system_dns_and_reports_udp_bound() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let config = Config {
                tti_ms: 10,
                terminate_linger_ms: 10,
                ..Config::default()
            };
            let mut listener = KcpListener::bind(
                "127.0.0.1:0".parse().unwrap(),
                config.clone(),
                StreamOptions::default(),
            )
            .await
            .unwrap();
            let destination = Destination::new("must-not-query-system-dns.invalid", 443).unwrap();
            let (mut client, bound) =
                connect_destination(&destination, Some(&[listener.local_addr()]), config)
                    .await
                    .unwrap();
            assert!(bound.ip().is_loopback());
            assert_ne!(bound.port(), 0);
            let sending = async {
                client.write_all(b"resolved UDP").await.unwrap();
                client.flush().await.unwrap();
            };
            let receiving = async {
                let (mut stream, peer) = listener.accept().await.unwrap();
                assert_eq!(peer, bound);
                let mut payload = [0; 12];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"resolved UDP");
                stream
            };
            let (_, server) = tokio::join!(sending, receiving);
            drop(client);
            drop(server);
            listener.close().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn empty_or_excessive_resolution_never_falls_back_to_dns() {
        let destination = Destination::new("must-not-query-system-dns.invalid", 443).unwrap();
        let error = connect_destination(&destination, Some(&[]), Config::default())
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        let addresses = vec!["127.0.0.1:443".parse().unwrap(); 65];
        let error = connect_destination(&destination, Some(&addresses), Config::default())
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn dropping_runtime_stream_releases_udp_without_default_linger() {
        use std::time::Duration;
        use tokio::net::UdpSocket;

        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = Destination::from(blackhole.local_addr().unwrap());
        // The ordinary configuration has an eight-second termination linger.
        let config = Config::default();
        assert_eq!(config.terminate_linger_ms, 8_000);
        let (stream, bound) = connect_destination(&destination, None, config)
            .await
            .unwrap();
        // Confirm the driver is active, and keep the remote socket bound so an
        // ICMP error cannot release the local socket and make this test pass.
        let mut packet = [0; 1350];
        let (_, source) =
            tokio::time::timeout(Duration::from_millis(800), blackhole.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, bound);
        assert!(
            matches!(UdpSocket::bind(bound).await, Err(error) if error.kind() == io::ErrorKind::AddrInUse)
        );
        drop(stream);
        let rebound = tokio::time::timeout(Duration::from_millis(800), async {
            loop {
                match UdpSocket::bind(bound).await {
                    Ok(socket) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        tokio::task::yield_now().await
                    }
                    Err(error) => panic!("unexpected UDP rebind failure: {error}"),
                }
            }
        })
        .await
        .expect("runtime KCP drop retained the UDP socket instead of cancelling");
        assert_eq!(rebound.local_addr().unwrap(), bound);
    }
}
