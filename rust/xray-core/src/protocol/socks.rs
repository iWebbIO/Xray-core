use anyhow::{Context, Result, bail, ensure};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Reply, Request};
use crate::{address::Destination, config::SocksSettings};

/// UDP source endpoint requested on the authenticated TCP control connection.
/// Port zero is valid here; it means learn the port from the first valid packet.
/// No success response is emitted until the caller actually binds a relay.
#[derive(Clone, Debug)]
pub struct AssociateRequest {
    pub requested_source: Destination,
    pub user: String,
}

pub enum Handshake {
    Connect(Request),
    Associate(AssociateRequest),
}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &SocksSettings,
) -> Result<Request> {
    match stream.read_u8().await? {
        4 => handshake4(stream, settings).await,
        5 => match handshake5(stream, settings, false).await? {
            Handshake::Connect(request) => Ok(request),
            Handshake::Associate(_) => unreachable!("UDP disabled by this API"),
        },
        version => bail!("unsupported SOCKS version {version}"),
    }
}

/// Authenticate and parse CONNECT or UDP ASSOCIATE. SOCKS4 remains CONNECT-only.
/// UDP requires settings.udp; all successful response bytes remain caller-owned.
pub async fn handshake_with_udp<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &SocksSettings,
) -> Result<Handshake> {
    match stream.read_u8().await? {
        4 => handshake4(stream, settings).await.map(Handshake::Connect),
        5 => handshake5(stream, settings, true).await,
        version => bail!("unsupported SOCKS version {version}"),
    }
}

async fn null_string<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String> {
    let mut bytes = Vec::new();
    for _ in 0..=255 {
        let byte = reader.read_u8().await?;
        if byte == 0 {
            return String::from_utf8(bytes).context("invalid SOCKS4 string");
        }
        bytes.push(byte);
    }
    bail!("SOCKS4 string exceeds 255 bytes")
}

async fn handshake4<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &SocksSettings,
) -> Result<Request> {
    if settings.auth == "password" {
        Reply::Socks4.failure(stream, 1).await?;
        bail!("SOCKS4 cannot authenticate password accounts");
    }
    let command = stream.read_u8().await?;
    let port = stream.read_u16().await?;
    let mut ip = [0; 4];
    stream.read_exact(&mut ip).await?;
    let _user = null_string(stream).await?;
    let host = if ip[0] == 0 {
        null_string(stream).await?
    } else {
        std::net::Ipv4Addr::from(ip).to_string()
    };
    if command != 1 {
        Reply::Socks4.failure(stream, 7).await?;
        bail!("unsupported SOCKS4 command {command}");
    }
    Ok(Request {
        level: 0,
        destination: Destination::new(&host, port)?,
        user: String::new(),
        initial_payload: vec![],
        reply: Reply::Socks4,
    })
}

async fn credentials<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u8().await? as usize;
    ensure!(len > 0, "empty SOCKS5 credential");
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn handshake5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    settings: &SocksSettings,
    allow_udp: bool,
) -> Result<Handshake> {
    let count = stream.read_u8().await? as usize;
    let mut methods = vec![0; count];
    stream.read_exact(&mut methods).await?;
    let required = if settings.auth == "password" { 2 } else { 0 };
    if !methods.contains(&required) {
        stream.write_all(&[5, 255]).await?;
        bail!("no acceptable SOCKS5 authentication method");
    }
    stream.write_all(&[5, required]).await?;
    let mut user = String::new();
    if required == 2 {
        if stream.read_u8().await? != 1 {
            stream.write_all(&[1, 255]).await?;
            bail!("invalid SOCKS5 authentication version");
        }
        let username = credentials(stream).await?;
        let password = credentials(stream).await?;
        let matched = settings
            .accounts
            .iter()
            .rev()
            .find(|account| account.user.as_bytes() == username);
        let valid =
            matched.is_some_and(|account| bool::from(account.pass.as_bytes().ct_eq(&password)));
        stream.write_all(&[1, if valid { 0 } else { 255 }]).await?;
        ensure!(valid, "SOCKS5 authentication failed");
        user = String::from_utf8(username).context("invalid SOCKS5 username")?;
    }
    let version = stream.read_u8().await?;
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    if version != 5 || reserved != 0 {
        Reply::Socks5.failure(stream, 1).await?;
        bail!("invalid SOCKS5 request header");
    }
    let associate = command == 3 && allow_udp && settings.udp;
    if !matches!(command, 1 | 0xf0 | 0xf1) && !associate {
        Reply::Socks5.failure(stream, 7).await?;
        bail!("SOCKS5 command {command} is not supported");
    }
    let destination = match Destination::read_socks(stream).await {
        Ok(destination) if destination.port != 0 || associate => destination,
        result => {
            Reply::Socks5.failure(stream, 8).await?;
            bail!("invalid SOCKS5 destination: {result:?}");
        }
    };
    if associate {
        return Ok(Handshake::Associate(AssociateRequest {
            requested_source: destination,
            user,
        }));
    }
    Ok(Handshake::Connect(Request {
        level: 0,
        destination,
        user,
        initial_payload: vec![],
        reply: Reply::Socks5,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address::Address, config::Account};
    use std::{net::Ipv4Addr, time::Duration};
    use tokio::{io::duplex, time::timeout};

    #[tokio::test]
    async fn udp_associate_accepts_zero_endpoint_and_emits_no_premature_success() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move {
            let result = handshake_with_udp(
                &mut server,
                &SocksSettings {
                    udp: true,
                    ..Default::default()
                },
            )
            .await;
            (result, server)
        });
        client
            .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut negotiation = [0; 2];
        client.read_exact(&mut negotiation).await.unwrap();
        assert_eq!(negotiation, [5, 0]);
        let (result, _server) = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        let Handshake::Associate(request) = result.unwrap() else {
            panic!("expected association")
        };
        assert_eq!(request.requested_source.port, 0);
        assert_eq!(
            request.requested_source.address,
            Address::Ip(Ipv4Addr::UNSPECIFIED.into())
        );
        assert!(
            timeout(Duration::from_millis(20), client.read_u8())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn association_reuses_password_authentication_and_preserves_source_port() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move {
            handshake_with_udp(
                &mut server,
                &SocksSettings {
                    udp: true,
                    auth: "password".into(),
                    accounts: vec![Account {
                        user: "alice".into(),
                        pass: "secret".into(),
                    }],
                    ..Default::default()
                },
            )
            .await
        });
        client
            .write_all(
                b"\x05\x01\x02\x01\x05alice\x06secret\x05\x03\x00\x01\x00\x00\x00\x00\x12\x34",
            )
            .await
            .unwrap();
        let mut replies = [0; 4];
        client.read_exact(&mut replies).await.unwrap();
        assert_eq!(replies, [5, 2, 1, 0]);
        let Handshake::Associate(request) = timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        else {
            panic!("expected association")
        };
        assert_eq!(request.user, "alice");
        assert_eq!(request.requested_source.port, 0x1234);
    }

    #[tokio::test]
    async fn old_api_and_disabled_udp_reject_association_with_command_error() {
        for old_api in [true, false] {
            let (mut client, mut server) = duplex(256);
            let task = tokio::spawn(async move {
                let settings = SocksSettings {
                    udp: old_api,
                    ..Default::default()
                };
                if old_api {
                    handshake(&mut server, &settings).await.map(|_| ())
                } else {
                    handshake_with_udp(&mut server, &settings).await.map(|_| ())
                }
            });
            client
                .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut replies = [0; 12];
            client.read_exact(&mut replies).await.unwrap();
            assert_eq!(&replies[..5], &[5, 0, 5, 7, 0]);
            assert!(
                timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn new_api_keeps_connect_and_legacy_tor_commands() {
        for command in [1, 0xf0, 0xf1] {
            let (mut client, mut server) = duplex(256);
            let task = tokio::spawn(async move {
                handshake_with_udp(&mut server, &SocksSettings::default()).await
            });
            client
                .write_all(&[5, 1, 0, 5, command, 0, 1, 127, 0, 0, 1, 0, 53])
                .await
                .unwrap();
            let Handshake::Connect(request) = timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap()
            else {
                panic!("expected connect")
            };
            assert_eq!(request.destination.port, 53);
        }
    }
}
