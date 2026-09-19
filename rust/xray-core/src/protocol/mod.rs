pub mod freedom;
pub mod http;
pub mod hysteria;
pub mod outbound;
pub mod shadowsocks;
pub mod shadowsocks2022;
pub mod shadowsocks_session;
pub mod shadowsocks_udp;
pub mod socks;
pub mod trojan;
pub mod tun;
pub mod udp;
pub mod vless;
pub mod vless_security;
pub mod vmess;
pub mod wireguard;

use crate::address::Destination;

pub struct Request {
    pub destination: Destination,
    pub user: String,
    pub initial_payload: Vec<u8>,
    pub reply: Reply,
}

#[derive(Clone, Copy)]
pub enum Reply {
    None,
    Socks4,
    Socks5,
    HttpConnect,
    HttpForward,
    Vless,
}

impl Reply {
    pub async fn success<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        bound: std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::None | Self::HttpForward => (),
            Self::Vless => writer.write_all(&[0, 0]).await?,
            Self::HttpConnect => {
                writer
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await?
            }
            Self::Socks4 => {
                let ip = match bound.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    _ => [0; 4],
                };
                writer.write_all(&[0, 90]).await?;
                writer.write_u16(bound.port()).await?;
                writer.write_all(&ip).await?;
            }
            Self::Socks5 => {
                writer.write_all(&[5, 0, 0]).await?;
                Destination::from(bound).write_socks(writer).await?;
            }
        }
        Ok(())
    }

    pub async fn failure<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        code: u8,
    ) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::None | Self::Vless => (),
            Self::HttpConnect | Self::HttpForward => writer
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await?,
            Self::Socks4 => writer.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?,
            Self::Socks5 => writer.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
        }
        Ok(())
    }
}
