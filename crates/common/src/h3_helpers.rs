//! Helpers for building HTTP/3 servers and clients using quinn + h3.

use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::CertificateDer;
use std::{net::SocketAddr, path::Path, sync::Arc};

/// Load TLS certificates from PEM files and create a quinn server config.
pub fn make_server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_ref())
            .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_ref())?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path.display()))?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    )))
}

/// Load a CA certificate and create a quinn client config that trusts it.
pub fn make_client_config(ca_cert_path: &Path) -> Result<ClientConfig> {
    let ca_pem = std::fs::read(ca_cert_path)?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_pem.as_ref())
            .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert)?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    )))
}

/// Create a bound quinn Endpoint for serving HTTP/3.
pub fn make_server_endpoint(addr: SocketAddr, server_cfg: ServerConfig) -> Result<Endpoint> {
    Ok(Endpoint::server(server_cfg, addr)?)
}

/// Create an unbound quinn Endpoint for client use.
pub fn make_client_endpoint(ca_cert_path: &Path) -> Result<Endpoint> {
    let client_cfg = make_client_config(ca_cert_path)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}
