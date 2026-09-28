//! Destination headers and authenticated salt admission for legacy AEAD TCP.
use super::{
    Reply, Request,
    shadowsocks::{AeadReader, AeadWriter, CipherKind, password_to_key},
};
use crate::{
    address::Destination,
    transport::{BoxStream, Joined},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWriteExt};
use zeroize::Zeroizing;

#[derive(Default)]
struct ReplayCache {
    seen: HashSet<Vec<u8>>,
    order: VecDeque<(Instant, Vec<u8>)>,
}
#[derive(Clone)]
pub struct Account {
    pub kind: CipherKind,
    pub email: String,
    key: Arc<Zeroizing<Vec<u8>>>,
    salts: Arc<Mutex<ReplayCache>>,
}
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksAccount")
            .field("kind", &self.kind)
            .field("email", &self.email)
            .finish_non_exhaustive()
    }
}
impl Account {
    /// The derived AEAD key material and cipher kind (for the UDP codec).
    pub fn aead_material(&self) -> (CipherKind, zeroize::Zeroizing<Vec<u8>>) {
        (
            self.kind,
            zeroize::Zeroizing::new(self.key.as_slice().to_vec()),
        )
    }

    pub fn new(kind: CipherKind, password: &str, email: String) -> Result<Self> {
        ensure!(!password.is_empty(), "Shadowsocks password is required");
        Ok(Self {
            kind,
            email,
            key: Arc::new(password_to_key(kind, password.as_bytes())),
            salts: Arc::new(Mutex::new(ReplayCache::default())),
        })
    }
    fn admit_salt(&self, salt: &[u8]) -> Result<()> {
        let mut cache = self
            .salts
            .lock()
            .map_err(|_| anyhow::anyhow!("Shadowsocks replay guard poisoned"))?;
        let now = Instant::now();
        while cache
            .order
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) >= Duration::from_secs(600))
        {
            let (_, expired) = cache.order.pop_front().unwrap();
            cache.seen.remove(&expired);
        }
        ensure!(!cache.seen.contains(salt), "replayed Shadowsocks salt");
        ensure!(
            cache.seen.len() < 65_536,
            "Shadowsocks replay guard capacity reached"
        );
        cache.seen.insert(salt.to_vec());
        cache.order.push_back((now, salt.to_vec()));
        Ok(())
    }
}
pub async fn accept(stream: BoxStream, account: &Account) -> Result<(BoxStream, Request)> {
    let (read, write) = tokio::io::split(stream);
    let mut reader = AeadReader::from_key(read, account.kind, &account.key)?;
    let destination = Destination::read_socks(&mut reader)
        .await
        .context("Shadowsocks destination header")?;
    ensure!(
        destination.port != 0,
        "Shadowsocks destination port is zero"
    );
    account.admit_salt(
        reader
            .salt()
            .context("missing authenticated Shadowsocks salt")?,
    )?;
    let writer = AeadWriter::from_key(write, account.kind, &account.key)?;
    account.admit_salt(writer.salt())?;
    let request = Request {
        level: 0,
        destination,
        user: account.email.clone(),
        initial_payload: Vec::new(),
        reply: Reply::None,
    };
    Ok((Box::new(Joined { reader, writer }), request))
}
pub async fn connect(
    stream: BoxStream,
    account: &Account,
    target: &Destination,
) -> Result<BoxStream> {
    let (read, write) = tokio::io::split(stream);
    let reader = AeadReader::from_key(read, account.kind, &account.key)?;
    let mut writer = AeadWriter::from_key(write, account.kind, &account.key)?;
    account.admit_salt(writer.salt())?;
    target.write_socks(&mut writer).await?;
    writer.flush().await?;
    Ok(Box::new(Joined {
        reader: CheckedReader {
            reader,
            account: account.clone(),
            checked: false,
        },
        writer,
    }))
}
struct CheckedReader<R> {
    reader: AeadReader<R>,
    account: Account,
    checked: bool,
}
impl<R: AsyncRead + Unpin> AsyncRead for CheckedReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{Poll, ready};
        let this = self.get_mut();
        if !this.checked && buf.remaining() != 0 {
            let mut byte = [0; 1];
            let mut first = tokio::io::ReadBuf::new(&mut byte);
            ready!(std::pin::Pin::new(&mut this.reader).poll_read(cx, &mut first))?;
            if first.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            let salt = this
                .reader
                .salt()
                .ok_or_else(|| std::io::Error::other("missing Shadowsocks response salt"))?;
            this.account
                .admit_salt(salt)
                .map_err(std::io::Error::other)?;
            this.checked = true;
            buf.put_slice(first.filled());
            return Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_replayed_authenticated_request_before_routing() {
        let account = Account::new(CipherKind::Aes128Gcm, "password", String::new()).unwrap();
        let target = Destination::new("example.org", 443).unwrap();
        let mut encoded =
            AeadWriter::with_salt(Vec::new(), account.kind, &account.key, &[3; 16]).unwrap();
        target.write_socks(&mut encoded).await.unwrap();
        encoded.flush().await.unwrap();
        let wire = encoded.into_inner();
        for allowed in [true, false] {
            let (mut client, server) = tokio::io::duplex(1024);
            client.write_all(&wire).await.unwrap();
            client.shutdown().await.unwrap();
            assert_eq!(accept(Box::new(server), &account).await.is_ok(), allowed);
        }
    }
}
