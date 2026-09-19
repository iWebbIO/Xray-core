//! Native TLS byte-stream transport. REALITY is a separate protocol.
//!
//! Configuration follows `infra/conf/transport_security.go`. Options requiring
//! unsupported handshake behavior fail during configuration, before any dial.
use std::{
    fmt, fs,
    io::BufReader,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore, ServerConfig, SignatureScheme, SupportedCipherSuite,
        SupportedProtocolVersion,
        client::{ResolvesClientCert, Resumption},
        crypto::{CryptoProvider, ring},
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        server::{ClientHello, ParsedCertificate, ResolvesServerCert},
        sign::CertifiedKey,
    },
};

use super::BoxStream;

const CERTIFICATE_RELOAD_INTERVAL: Duration = Duration::from_secs(3600);

/// Xray's TLS settings. Unknown JSON fields are errors to prevent silent loss
/// of security settings. Recognized, unsupported options are rejected by validate.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsSettings {
    pub allow_insecure: bool,
    pub certificates: Vec<TlsCertificate>,
    pub server_name: String,
    #[serde(deserialize_with = "string_list")]
    pub alpn: Vec<String>,
    pub enable_session_resumption: bool,
    pub disable_system_root: bool,
    pub min_version: String,
    pub max_version: String,
    pub cipher_suites: String,
    pub fingerprint: String,
    pub reject_unknown_sni: bool,
    #[serde(deserialize_with = "string_list")]
    pub curve_preferences: Vec<String>,
    pub master_key_log: String,
    pub pinned_peer_cert_sha256: String,
    pub verify_peer_cert_by_name: String,
    pub ech_server_keys: String,
    pub ech_config_list: String,
    pub ech_sockopt: Option<serde_json::Value>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsCertificate {
    pub certificate_file: String,
    pub certificate: Vec<String>,
    pub key_file: String,
    pub key: Vec<String>,
    pub usage: String,
    pub ocsp_stapling: u64,
    pub one_time_loading: bool,
    pub build_chain: bool,
}

// A configuration's debug output must never expose PEM private keys.
impl fmt::Debug for TlsCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCertificate")
            .field("certificate_file", &self.certificate_file)
            .field("key_file", &self.key_file)
            .field("usage", &self.usage)
            .field("one_time_loading", &self.one_time_loading)
            .finish_non_exhaustive()
    }
}

fn string_list<'de, D: Deserializer<'de>>(de: D) -> std::result::Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringList {
        List(Vec<String>),
        String(String),
        Null,
    }
    Ok(match StringList::deserialize(de)? {
        StringList::List(list) => list,
        StringList::String(value) => value.split(',').map(str::to_owned).collect(),
        StringList::Null => Vec::new(),
    })
}

impl TlsSettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.allow_insecure,
            "TLS allowInsecure has been removed; configure a trusted certificate instead"
        );
        ensure!(
            self.fingerprint.is_empty(),
            "TLS fingerprint impersonation is not implemented in the native Rust TLS transport"
        );
        ensure!(
            self.master_key_log.is_empty() || self.master_key_log == "none",
            "TLS masterKeyLog is not implemented"
        );
        ensure!(
            self.pinned_peer_cert_sha256.is_empty(),
            "TLS pinnedPeerCertSha256 verification is not implemented"
        );
        ensure!(
            self.verify_peer_cert_by_name.is_empty(),
            "TLS verifyPeerCertByName verification is not implemented"
        );
        ensure!(
            self.ech_server_keys.is_empty()
                && self.ech_config_list.is_empty()
                && self.ech_sockopt.is_none(),
            "TLS ECH is not implemented"
        );
        ensure!(
            !self.server_name.eq_ignore_ascii_case("frommitm"),
            "TLS serverName fromMitm requires MITM support, which is not implemented"
        );
        if !self.server_name.is_empty() {
            self.server_name("")?;
        }
        self.protocol_versions()?;
        self.provider()?;
        let mut alpn_size = 0usize;
        for value in &self.alpn {
            ensure!(
                !value.eq_ignore_ascii_case("frommitm"),
                "TLS ALPN fromMitm is not implemented"
            );
            ensure!(
                !value.is_empty() && value.len() <= 255,
                "TLS ALPN identifiers must contain 1 to 255 bytes"
            );
            alpn_size += 1 + value.len();
        }
        ensure!(
            alpn_size <= u16::MAX as usize,
            "TLS ALPN list exceeds the protocol limit"
        );
        for cert in &self.certificates {
            cert.validate()?;
        }
        Ok(())
    }

    /// The configured name overrides the destination host. IP destinations are
    /// validated as IP SANs and, as required by TLS, are not sent as DNS SNI.
    pub fn server_name(&self, destination_host: &str) -> Result<ServerName<'static>> {
        let name = if self.server_name.is_empty() {
            destination_host
        } else {
            &self.server_name
        };
        let name = name
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(name);
        ServerName::try_from(name.to_owned()).context("invalid TLS serverName or destination host")
    }

    fn protocol_versions(&self) -> Result<Vec<&'static SupportedProtocolVersion>> {
        fn version(value: &str, default: u8) -> Result<u8> {
            match value {
                "" => Ok(default),
                "1.2" => Ok(12),
                "1.3" => Ok(13),
                "1.0" | "1.1" => bail!("TLS versions below 1.2 are not supported by rustls"),
                _ => bail!("unknown TLS version {value:?}; expected 1.2 or 1.3"),
            }
        }
        let min = version(&self.min_version, 12)?;
        let max = version(&self.max_version, 13)?;
        ensure!(min <= max, "TLS minVersion exceeds maxVersion");
        Ok([&rustls::version::TLS13, &rustls::version::TLS12]
            .into_iter()
            .filter(|v| match v.version {
                rustls::ProtocolVersion::TLSv1_3 => max >= 13,
                _ => min <= 12,
            })
            .collect())
    }

    fn provider(&self) -> Result<Arc<CryptoProvider>> {
        let mut provider = ring::default_provider();
        if !self.curve_preferences.is_empty() {
            provider.kx_groups.clear();
            for name in &self.curve_preferences {
                let group = match name.to_ascii_lowercase().as_str() {
                    "x25519" => ring::kx_group::X25519,
                    "curvep256" => ring::kx_group::SECP256R1,
                    "curvep384" => ring::kx_group::SECP384R1,
                    _ => bail!(
                        "TLS curvePreferences group {name:?} is not supported by the ring provider"
                    ),
                };
                ensure!(
                    !provider
                        .kx_groups
                        .iter()
                        .any(|old| old.name() == group.name()),
                    "duplicate TLS curvePreferences group {name:?}"
                );
                provider.kx_groups.push(group);
            }
        }
        if !self.cipher_suites.is_empty() {
            let available = provider.cipher_suites.clone();
            // Like Go's CipherSuites field, this option controls TLS 1.2 only.
            provider
                .cipher_suites
                .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
            for name in self.cipher_suites.split(':').map(str::trim) {
                let suite = available
                    .iter()
                    .find(|suite| {
                        matches!(suite, SupportedCipherSuite::Tls12(_))
                            && format!("{:?}", suite.suite()) == name
                    })
                    .with_context(|| {
                        format!("TLS cipherSuites entry {name:?} is not a supported TLS 1.2 cipher")
                    })?;
                ensure!(
                    !provider
                        .cipher_suites
                        .iter()
                        .any(|old| old.suite() == suite.suite()),
                    "duplicate TLS cipherSuites entry {name:?}"
                );
                provider.cipher_suites.push(*suite);
            }
        }
        Ok(Arc::new(provider))
    }

    fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        if self.alpn.is_empty() {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            self.alpn
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect()
        }
    }

    /// Loads native operating-system roots and explicit `usage: verify` CAs.
    /// On platforms without a native store, Mozilla's WebPKI roots are used.
    /// `disableSystemRoot: true` disables both sources of public roots.
    pub fn root_store(&self) -> Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        if !self.disable_system_root {
            if cfg!(any(unix, windows)) {
                let native = rustls_native_certs::load_native_certs();
                for cert in native.certs {
                    roots
                        .add(cert)
                        .context("failed to parse a native TLS root certificate")?;
                }
                // An empty or failed native store must never silently broaden
                // trust to roots that an administrator may have removed.
                if roots.is_empty() && !native.errors.is_empty() {
                    bail!("could not load native TLS roots: {:?}", native.errors);
                }
            } else {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
        }
        for cert in self.certificates.iter().filter(|cert| cert.is_verify()) {
            for der in cert.certificates()? {
                roots
                    .add(der)
                    .context("invalid TLS certificate with usage verify")?;
            }
        }
        ensure!(
            !roots.is_empty(),
            "TLS trust store is empty; provide certificates with usage verify or enable system roots"
        );
        Ok(roots)
    }

    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>> {
        self.validate()?;
        ensure!(
            !self.reject_unknown_sni,
            "TLS rejectUnknownSni applies only to inbound TLS"
        );
        ensure!(
            self.certificates
                .iter()
                .filter(|cert| !cert.is_verify())
                .count()
                <= 1,
            "TLS outbound currently supports one client identity; selection between multiple client certificates by issuer is not implemented"
        );
        let provider = self.provider()?;
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&self.protocol_versions()?)
            .context("invalid TLS client protocol/cipher configuration")?
            .with_root_certificates(self.root_store()?);
        let mut config = if self.certificates.iter().any(|cert| !cert.is_verify()) {
            builder.with_client_cert_resolver(Arc::new(CertificateResolver::new(self, provider)?))
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = self.alpn_protocols();
        config.resumption = if self.enable_session_resumption {
            Resumption::in_memory_sessions(256)
        } else {
            Resumption::disabled()
        };
        Ok(Arc::new(config))
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>> {
        self.validate()?;
        let provider = self.provider()?;
        let resolver = Arc::new(CertificateResolver::new(self, provider.clone())?);
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&self.protocol_versions()?)
            .context("invalid TLS server protocol/cipher configuration")?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.alpn_protocols = self.alpn_protocols();
        if self.enable_session_resumption {
            config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
            config.ticketer =
                ring::Ticketer::new().context("failed to initialize TLS session ticket keys")?;
        } else {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
        }
        Ok(Arc::new(config))
    }
}

impl TlsCertificate {
    fn is_verify(&self) -> bool {
        self.usage.eq_ignore_ascii_case("verify")
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                self.usage.to_ascii_lowercase().as_str(),
                "" | "encipherment" | "verify"
            ),
            "TLS certificate usage {:?} is not supported; certificate issuing is not implemented",
            self.usage
        );
        ensure!(
            self.ocsp_stapling == 0,
            "TLS certificate ocspStapling is not implemented"
        );
        ensure!(
            !self.build_chain,
            "TLS certificate buildChain requires certificate issuing, which is not implemented"
        );
        ensure!(
            !self.certificate_file.is_empty() || !self.certificate.is_empty(),
            "TLS certificate requires certificateFile or certificate"
        );
        ensure!(
            self.certificate_file.is_empty() || self.certificate.is_empty(),
            "TLS certificateFile and certificate cannot both be set"
        );
        ensure!(
            self.key_file.is_empty() || self.key.is_empty(),
            "TLS keyFile and key cannot both be set"
        );
        if self.is_verify() {
            ensure!(
                self.key_file.is_empty() && self.key.is_empty(),
                "TLS verification certificates must not include a private key"
            );
        } else {
            ensure!(
                !self.key_file.is_empty() || !self.key.is_empty(),
                "TLS encipherment certificate requires keyFile or key"
            );
        }
        Ok(())
    }

    fn certificates(&self) -> Result<Vec<CertificateDer<'static>>> {
        let pem = read_pem(&self.certificate_file, &self.certificate, "certificate")?;
        let certs = rustls_pemfile::certs(&mut BufReader::new(pem.as_slice()))
            .collect::<std::io::Result<Vec<_>>>()
            .context("failed to parse TLS certificate PEM")?;
        ensure!(
            !certs.is_empty(),
            "TLS certificate PEM contains no certificates"
        );
        Ok(certs)
    }

    fn private_key(&self) -> Result<PrivateKeyDer<'static>> {
        let pem = read_pem(&self.key_file, &self.key, "private key")?;
        let mut reader = BufReader::new(pem.as_slice());
        let key = rustls_pemfile::private_key(&mut reader)
            .context("failed to parse TLS private key PEM")?
            .context("TLS key PEM contains no supported unencrypted private key")?;
        ensure!(
            rustls_pemfile::private_key(&mut reader)?.is_none(),
            "TLS key PEM contains more than one private key"
        );
        Ok(key)
    }

    fn certified_key(&self, provider: &CryptoProvider) -> Result<Arc<CertifiedKey>> {
        let certs = self.certificates()?;
        ParsedCertificate::try_from(&certs[0]).context("invalid TLS leaf certificate")?;
        let key = CertifiedKey::from_der(certs, self.private_key()?, provider)
            .context("invalid TLS certificate/private-key pair")?;
        key.keys_match()
            .context("TLS certificate and private key do not match")?;
        Ok(Arc::new(key))
    }

    fn reloadable(&self) -> bool {
        !self.one_time_loading && (!self.certificate_file.is_empty() || !self.key_file.is_empty())
    }
}

fn read_pem(path: &str, inline: &[String], kind: &str) -> Result<Vec<u8>> {
    if path.is_empty() {
        Ok(inline.join("\n").into_bytes())
    } else {
        fs::read(path).with_context(|| format!("failed to read TLS {kind} file {path:?}"))
    }
}

#[derive(Debug)]
struct CertificateResolver {
    sources: Vec<TlsCertificate>,
    provider: Arc<CryptoProvider>,
    state: Mutex<CertificateState>,
    reject_unknown_sni: bool,
}

#[derive(Debug)]
struct CertificateState {
    keys: Vec<Arc<CertifiedKey>>,
    last_reload: Instant,
}

impl CertificateResolver {
    fn new(settings: &TlsSettings, provider: Arc<CryptoProvider>) -> Result<Self> {
        let sources: Vec<_> = settings
            .certificates
            .iter()
            .filter(|cert| !cert.is_verify())
            .cloned()
            .collect();
        ensure!(
            !sources.is_empty(),
            "TLS server requires an encipherment certificate and private key"
        );
        let keys = sources
            .iter()
            .map(|cert| cert.certified_key(&provider))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            sources,
            provider,
            state: Mutex::new(CertificateState {
                keys,
                last_reload: Instant::now(),
            }),
            reject_unknown_sni: settings.reject_unknown_sni,
        })
    }

    fn keys(&self) -> Vec<Arc<CertifiedKey>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.last_reload.elapsed() >= CERTIFICATE_RELOAD_INTERVAL {
            for (index, source) in self
                .sources
                .iter()
                .enumerate()
                .filter(|(_, source)| source.reloadable())
            {
                match source.certified_key(&self.provider) {
                    Ok(key) => state.keys[index] = key,
                    Err(error) => {
                        tracing::warn!(%error, "TLS certificate reload failed; retaining the last valid certificate")
                    }
                }
            }
            state.last_reload = Instant::now();
        }
        state.keys.clone()
    }

    fn for_name(
        &self,
        name: Option<&str>,
        schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        let keys = self.keys();
        let suitable = |key: &&Arc<CertifiedKey>| key.key.choose_scheme(schemes).is_some();
        if let Some(name) = name.and_then(|name| ServerName::try_from(name.to_owned()).ok())
            && let Some(key) = keys.iter().filter(suitable).find(|key| {
                ParsedCertificate::try_from(&key.cert[0])
                    .and_then(|cert| rustls::client::verify_server_name(&cert, &name))
                    .is_ok()
            })
        {
            return Some(key.clone());
        }
        if self.reject_unknown_sni {
            None
        } else {
            keys.iter().find(suitable).cloned()
        }
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.for_name(hello.server_name(), hello.signature_schemes())
    }
}

impl ResolvesClientCert for CertificateResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.keys()
            .into_iter()
            .find(|key| key.key.choose_scheme(sigschemes).is_some())
    }

    fn has_certs(&self) -> bool {
        !self.sources.is_empty()
    }
}

#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    settings: TlsSettings,
}

impl TlsClient {
    pub fn new(settings: &TlsSettings) -> Result<Self> {
        Ok(Self {
            connector: TlsConnector::from(settings.build_client_config()?),
            settings: settings.clone(),
        })
    }

    pub async fn connect(&self, stream: BoxStream, destination_host: &str) -> Result<BoxStream> {
        self.connect_checked(stream, destination_host, None).await
    }

    /// Require the peer to negotiate the selected application protocol. An
    /// omitted ALPN response is rejected as well as a different protocol.
    pub async fn connect_with_alpn(
        &self,
        stream: BoxStream,
        destination_host: &str,
        required_alpn: &[u8],
    ) -> Result<BoxStream> {
        self.connect_checked(stream, destination_host, Some(required_alpn))
            .await
    }

    async fn connect_checked(
        &self,
        stream: BoxStream,
        destination_host: &str,
        required_alpn: Option<&[u8]>,
    ) -> Result<BoxStream> {
        let name = self.settings.server_name(destination_host)?;
        let stream = self
            .connector
            .connect(name, stream)
            .await
            .context("TLS client handshake failed")?;
        if let Some(required) = required_alpn {
            ensure!(
                stream.get_ref().1.alpn_protocol() == Some(required),
                "TLS peer did not negotiate required ALPN {:?}",
                String::from_utf8_lossy(required)
            );
        }
        Ok(Box::new(stream))
    }
}

#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
}

impl TlsServer {
    pub fn new(settings: &TlsSettings) -> Result<Self> {
        Ok(Self {
            acceptor: TlsAcceptor::from(settings.build_server_config()?),
        })
    }

    pub async fn accept(&self, stream: BoxStream) -> Result<BoxStream> {
        self.accept_checked(stream, None).await
    }

    /// Like accept, requiring an actual negotiated ALPN before returning bytes.
    pub async fn accept_with_alpn(
        &self,
        stream: BoxStream,
        required_alpn: &[u8],
    ) -> Result<BoxStream> {
        self.accept_checked(stream, Some(required_alpn)).await
    }

    async fn accept_checked(
        &self,
        stream: BoxStream,
        required_alpn: Option<&[u8]>,
    ) -> Result<BoxStream> {
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .context("TLS server handshake failed")?;
        if let Some(required) = required_alpn {
            ensure!(
                stream.get_ref().1.alpn_protocol() == Some(required),
                "TLS client did not negotiate required ALPN {:?}",
                String::from_utf8_lossy(required)
            );
        }
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn pair(name: &str) -> (TlsSettings, TlsSettings) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let cert = cert.pem().lines().map(str::to_owned).collect::<Vec<_>>();
        let server = TlsSettings {
            certificates: vec![TlsCertificate {
                certificate: cert.clone(),
                key: signing_key
                    .serialize_pem()
                    .lines()
                    .map(str::to_owned)
                    .collect(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let client = TlsSettings {
            server_name: name.to_owned(),
            disable_system_root: true,
            certificates: vec![TlsCertificate {
                certificate: cert,
                usage: "verify".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        (server, client)
    }

    #[tokio::test]
    async fn tls12_and_tls13_exchange_bytes_and_negotiate_alpn() {
        for version in ["1.2", "1.3"] {
            let (mut server_settings, mut client_settings) = pair("localhost");
            server_settings.min_version = version.into();
            server_settings.max_version = version.into();
            server_settings.alpn = vec!["test/1".into(), "h2".into()];
            client_settings.alpn = vec!["test/1".into()];
            let server = TlsAcceptor::from(server_settings.build_server_config().unwrap());
            let client = TlsConnector::from(client_settings.build_client_config().unwrap());
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let handshake = async {
                tokio::join!(
                    server.accept(server_io),
                    client.connect(client_settings.server_name("").unwrap(), client_io)
                )
            };
            let (server, client) = tokio::time::timeout(Duration::from_secs(5), handshake)
                .await
                .unwrap();
            let mut server = server.unwrap();
            let mut client = client.unwrap();
            assert_eq!(
                client.get_ref().1.alpn_protocol(),
                Some(b"test/1".as_slice())
            );
            assert_eq!(
                client.get_ref().1.protocol_version(),
                Some(if version == "1.2" {
                    rustls::ProtocolVersion::TLSv1_2
                } else {
                    rustls::ProtocolVersion::TLSv1_3
                })
            );
            client.write_all(b"native TLS request").await.unwrap();
            client.flush().await.unwrap();
            let mut request = [0; 18];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"native TLS request");
            server.write_all(b"response").await.unwrap();
            server.flush().await.unwrap();
            let mut response = [0; 8];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"response");
        }
    }

    #[tokio::test]
    async fn wrappers_compose_over_box_streams() {
        let (server, client) = pair("localhost");
        let server = TlsServer::new(&server).unwrap();
        let client = TlsClient::new(&client).unwrap();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let (server, client) = tokio::join!(
            server.accept(Box::new(server_io)),
            client.connect(Box::new(client_io), "127.0.0.1")
        );
        assert!(server.is_ok());
        assert!(client.is_ok());
    }

    async fn rejected(server: TlsSettings, client: TlsSettings) {
        let acceptor = TlsAcceptor::from(server.build_server_config().unwrap());
        let connector = TlsConnector::from(client.build_client_config().unwrap());
        let (client_io, server_io) = tokio::io::duplex(65536);
        let handshake = async {
            tokio::join!(
                acceptor.accept(server_io),
                connector.connect(client.server_name("").unwrap(), client_io)
            )
        };
        let (server, client) = tokio::time::timeout(Duration::from_secs(5), handshake)
            .await
            .unwrap();
        assert!(client.is_err());
        drop(server);
    }

    #[tokio::test]
    async fn rejects_untrusted_certificate_and_wrong_name() {
        let (server, mut client) = pair("localhost");
        client.server_name = "wrong.example".into();
        rejected(server, client).await;
        let (server, _) = pair("localhost");
        let (_, client) = pair("localhost");
        rejected(server, client).await;
    }

    #[tokio::test]
    async fn rejects_disjoint_alpn_and_tls_versions() {
        let (mut server, mut client) = pair("localhost");
        server.alpn = vec!["h2".into()];
        client.alpn = vec!["http/1.1".into()];
        rejected(server, client).await;
        let (mut server, mut client) = pair("localhost");
        server.min_version = "1.3".into();
        client.max_version = "1.2".into();
        rejected(server, client).await;
    }

    #[test]
    fn selects_certificates_by_sni_and_rejects_unknown_names() {
        let (mut server, _) = pair("first.example");
        let (other, _) = pair("second.example");
        server.certificates.extend(other.certificates);
        server.reject_unknown_sni = true;
        let resolver = CertificateResolver::new(&server, server.provider().unwrap()).unwrap();
        let schemes = [SignatureScheme::ECDSA_NISTP256_SHA256];
        let first = resolver.for_name(Some("first.example"), &schemes).unwrap();
        let second = resolver.for_name(Some("second.example"), &schemes).unwrap();
        assert_ne!(first.cert, second.cert);
        assert!(
            resolver
                .for_name(Some("unknown.example"), &schemes)
                .is_none()
        );
        assert!(resolver.for_name(None, &schemes).is_none());
    }

    #[test]
    fn rejects_invalid_or_unsupported_security_settings() {
        for json in [
            r#"{"allowInsecure":true}"#,
            r#"{"fingerprint":"chrome"}"#,
            r#"{"minVersion":"1.0"}"#,
            r#"{"minVersion":"1.3","maxVersion":"1.2"}"#,
            r#"{"pinnedPeerCertSha256":"00"}"#,
            r#"{"echConfigList":"AA=="}"#,
            r#"{"curvePreferences":["X25519MLKEM768"]}"#,
            r#"{"alpn":[""]}"#,
        ] {
            let settings: TlsSettings = serde_json::from_str(json).unwrap();
            assert!(settings.validate().is_err(), "unexpectedly accepted {json}");
        }
        assert!(serde_json::from_str::<TlsSettings>(r#"{"allowInsecureTypo":true}"#).is_err());
        let settings: TlsSettings =
            serde_json::from_str(r#"{"alpn":"h2,http/1.1","curvePreferences":"X25519,CurveP256"}"#)
                .unwrap();
        settings.validate().unwrap();
        assert_eq!(settings.alpn, ["h2", "http/1.1"]);
        assert!(
            TlsSettings {
                disable_system_root: true,
                ..Default::default()
            }
            .build_client_config()
            .is_err()
        );
    }

    #[test]
    fn rejects_mismatched_private_keys_and_redacts_keys_from_debug() {
        let (mut server, _) = pair("localhost");
        let (other, _) = pair("localhost");
        server.certificates[0].key = other.certificates[0].key.clone();
        assert!(server.build_server_config().is_err());
        assert!(!format!("{server:?}").contains("PRIVATE KEY"));
    }

    #[test]
    fn destination_names_and_ip_addresses() {
        let settings = TlsSettings::default();
        assert!(matches!(
            settings.server_name("example.org").unwrap(),
            ServerName::DnsName(_)
        ));
        assert!(matches!(
            settings.server_name("127.0.0.1").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(matches!(
            settings.server_name("[::1]").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(settings.server_name("example.org:443").is_err());
    }

    #[tokio::test]
    async fn client_certificate_authenticates_to_a_requiring_server() {
        let (server_settings, mut client_settings) = pair("localhost");
        let (identity, _) = pair("client.example");
        let mut client_roots = RootCertStore::empty();
        client_roots
            .add(identity.certificates[0].certificates().unwrap()[0].clone())
            .unwrap();
        client_settings.certificates.extend(identity.certificates);
        let provider = server_settings.provider().unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let mut config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(
                CertificateResolver::new(&server_settings, provider).unwrap(),
            ));
        config.alpn_protocols = server_settings.alpn_protocols();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let connector = TlsConnector::from(client_settings.build_client_config().unwrap());
        let (client_io, server_io) = tokio::io::duplex(65536);
        let handshake = async {
            tokio::join!(
                acceptor.accept(server_io),
                connector.connect(client_settings.server_name("").unwrap(), client_io)
            )
        };
        let (server, client) = tokio::time::timeout(Duration::from_secs(5), handshake)
            .await
            .unwrap();
        assert!(client.is_ok());
        let server = server.unwrap();
        assert_eq!(server.get_ref().1.peer_certificates().unwrap().len(), 1);
    }

    #[test]
    fn file_certificates_reload_atomically_and_keep_the_last_valid_pair() {
        struct Files {
            directory: std::path::PathBuf,
            certificate: std::path::PathBuf,
            key: std::path::PathBuf,
        }
        impl Drop for Files {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.certificate);
                let _ = fs::remove_file(&self.key);
                let _ = fs::remove_dir(&self.directory);
            }
        }
        let directory = std::env::temp_dir().join(format!(
            "xray-rust-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let files = Files {
            certificate: directory.join("cert.pem"),
            key: directory.join("key.pem"),
            directory,
        };
        let (original, _) = pair("localhost");
        fs::write(
            &files.certificate,
            original.certificates[0].certificate.join("\n"),
        )
        .unwrap();
        fs::write(&files.key, original.certificates[0].key.join("\n")).unwrap();
        let settings = TlsSettings {
            certificates: vec![TlsCertificate {
                certificate_file: files.certificate.to_string_lossy().into_owned(),
                key_file: files.key.to_string_lossy().into_owned(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let resolver = CertificateResolver::new(&settings, settings.provider().unwrap()).unwrap();
        let initial = resolver.keys()[0].clone();
        let (replacement, _) = pair("localhost");
        fs::write(
            &files.certificate,
            replacement.certificates[0].certificate.join("\n"),
        )
        .unwrap();
        resolver.state.lock().unwrap().last_reload = Instant::now() - CERTIFICATE_RELOAD_INTERVAL;
        // A certificate and key replaced in separate filesystem operations must
        // never expose an invalid intermediate pair to the next handshake.
        assert_eq!(resolver.keys()[0].cert, initial.cert);
        fs::write(&files.key, replacement.certificates[0].key.join("\n")).unwrap();
        resolver.state.lock().unwrap().last_reload = Instant::now() - CERTIFICATE_RELOAD_INTERVAL;
        assert_ne!(resolver.keys()[0].cert, initial.cert);

        let mut one_time_settings = settings;
        one_time_settings.certificates[0].one_time_loading = true;
        let one_time =
            CertificateResolver::new(&one_time_settings, one_time_settings.provider().unwrap())
                .unwrap();
        let loaded_once = one_time.keys()[0].clone();
        fs::write(
            &files.certificate,
            original.certificates[0].certificate.join("\n"),
        )
        .unwrap();
        fs::write(&files.key, original.certificates[0].key.join("\n")).unwrap();
        one_time.state.lock().unwrap().last_reload = Instant::now() - CERTIFICATE_RELOAD_INTERVAL;
        assert_eq!(one_time.keys()[0].cert, loaded_once.cert);
    }
}
