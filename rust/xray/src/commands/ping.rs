use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};

use super::certificate::CertificateInfo;

#[derive(Debug)]
struct InspectCertificate(Arc<CryptoProvider>);

/// The no-SNI probe intentionally inspects untrusted certificates, as the Go
/// diagnostic does. Handshake signatures are still cryptographically checked.
impl ServerCertVerifier for InspectCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(sni: bool, roots: RootCertStore) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let mut config = if sni {
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InspectCertificate(provider)))
            .with_no_client_auth()
    };
    config.enable_sni = sni;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn target(domain_with_port: &str) -> Result<(String, u16)> {
    ensure!(!domain_with_port.is_empty(), "domain not specified");
    if let Some(bracketed) = domain_with_port.strip_prefix('[') {
        if let Some((host, port)) = bracketed.split_once("]:") {
            return Ok((
                host.to_owned(),
                port.parse().context("invalid target port")?,
            ));
        }
        bail!("invalid bracketed target; use [IPv6]:port");
    }
    if domain_with_port.matches(':').count() == 1 {
        let (host, port) = domain_with_port.split_once(':').expect("one colon");
        ensure!(!host.is_empty(), "domain not specified");
        return Ok((
            host.to_owned(),
            port.parse().context("invalid target port")?,
        ));
    }
    Ok((domain_with_port.to_owned(), 443))
}

fn connection_details(connection: &rustls::ClientConnection) -> Result<String> {
    let version = match connection.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "",
    };
    let mut rows = vec![("TLS Version:".into(), version.into())];
    if let Some(group) = connection.negotiated_key_exchange_group() {
        let (post_quantum, name) = match u16::from(group.name()) {
            0x0017 => (false, "CurveP256".to_owned()),
            0x0018 => (false, "CurveP384".to_owned()),
            0x0019 => (false, "CurveP521".to_owned()),
            0x001d => (false, "X25519".to_owned()),
            0x11ec => (true, "X25519MLKEM768".to_owned()),
            value => (false, format!("CurveID({value})")),
        };
        rows.push((
            "TLS Post-Quantum key exchange:".into(),
            format!("{post_quantum} ({name})"),
        ));
    }
    let chain = connection.peer_certificates().unwrap_or_default();
    rows.push((
        "Certificate chain's total length:".into(),
        format!(
            "{} (certs count: {})",
            chain.iter().map(|cert| cert.len()).sum::<usize>(),
            chain.len()
        ),
    ));
    let parsed = chain
        .iter()
        .map(|cert| CertificateInfo::parse(cert.as_ref()))
        .collect::<Result<Vec<_>>>()?;
    // Source selects the last certificate with DNS SANs as the leaf and uses
    // only certificates without DNS SANs as CA rows.
    if let Some(leaf) = parsed.iter().rev().find(|cert| !cert.dns_names.is_empty()) {
        rows.push((
            "Cert's signature algorithm:".into(),
            leaf.signature_algorithm.clone(),
        ));
        rows.push((
            "Cert's publicKey algorithm:".into(),
            leaf.public_key_algorithm.clone(),
        ));
        rows.push(("Cert's leaf SHA256:".into(), leaf.hash()));
        for ca in parsed.iter().filter(|cert| cert.dns_names.is_empty()) {
            rows.push((format!("Cert's CA <{}> SHA256:", ca.common_name), ca.hash()));
        }
        rows.push((
            "Cert's allowed domains:".into(),
            format!("[{}]", leaf.dns_names.join(" ")),
        ));
    }
    Ok(super::table(&rows))
}

async fn probe(
    address: SocketAddr,
    domain: &str,
    config: ClientConfig,
    out: &mut impl Write,
) -> Result<()> {
    let stream = TcpStream::connect(address)
        .await
        .context("Failed to dial tcp")?;
    let server_name = ServerName::try_from(domain.to_owned()).context("invalid TLS server name")?;
    match TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
    {
        Ok(mut stream) => {
            writeln!(out, "Handshake succeeded")?;
            out.write_all(connection_details(stream.get_ref().1)?.as_bytes())?;
            let _ = stream.shutdown().await;
        }
        Err(error) => writeln!(out, "Handshake failure:  {error}")?,
    }
    Ok(())
}

pub(super) async fn run(domain_with_port: &str, ip: &str, out: &mut impl Write) -> Result<()> {
    writeln!(out, "TLS ping:  {domain_with_port}")?;
    let (domain, port) = target(domain_with_port)?;
    let address = if ip.is_empty() {
        tokio::net::lookup_host((domain.as_str(), port))
            .await
            .context("Failed to resolve IP")?
            .next()
            .context("Failed to resolve IP: no addresses")?
    } else {
        SocketAddr::new(
            ip.parse::<IpAddr>()
                .with_context(|| format!("invalid IP: {ip}"))?,
            port,
        )
    };
    // Source prints an unbracketed IP even for IPv6; retain that display.
    writeln!(out, "Using IP:  {}:{}", address.ip(), address.port())?;
    writeln!(out, "-------------------\nPinging without SNI")?;
    probe(
        address,
        &domain,
        client_config(false, RootCertStore::empty())?,
        out,
    )
    .await?;
    writeln!(out, "-------------------\nPinging with SNI")?;
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(native.certs);
    probe(address, &domain, client_config(true, roots)?, out).await?;
    writeln!(out, "-------------------\nTLS ping finished")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn target_port_and_ipv6_parsing() {
        assert_eq!(target("example.com").unwrap(), ("example.com".into(), 443));
        assert_eq!(
            target("example.com:8443").unwrap(),
            ("example.com".into(), 8443)
        );
        assert_eq!(target("[::1]:443").unwrap(), ("::1".into(), 443));
        assert_eq!(target("::1").unwrap(), ("::1".into(), 443));
        assert!(target("").is_err());
        assert!(target("example.com:bad").is_err());
        assert!(target("[::1]").is_err());
    }

    #[tokio::test]
    async fn tls_probes_verify_trust_and_report_negotiation() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = generated.cert.der().clone();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key.into())
        .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut names = Vec::new();
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.unwrap();
                if let Ok(stream) = acceptor.accept(stream).await {
                    names.push(stream.get_ref().1.server_name().map(str::to_owned));
                }
            }
            names
        });
        let mut output = Vec::new();
        probe(
            address,
            "localhost",
            client_config(false, RootCertStore::empty()).unwrap(),
            &mut output,
        )
        .await
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Handshake succeeded\n"));
        assert!(text.contains("TLS 1.3"));
        assert!(text.contains("false (X25519)"));
        assert!(text.contains("[localhost]"));
        let mut roots = RootCertStore::empty();
        roots.add(der).unwrap();
        let mut output = Vec::new();
        probe(
            address,
            "localhost",
            client_config(true, roots).unwrap(),
            &mut output,
        )
        .await
        .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("Handshake succeeded\n")
        );
        let mut output = Vec::new();
        probe(
            address,
            "localhost",
            client_config(true, RootCertStore::empty()).unwrap(),
            &mut output,
        )
        .await
        .unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .starts_with("Handshake failure:  ")
        );
        assert_eq!(task.await.unwrap(), [None, Some("localhost".into())]);
    }
}
