//! Client and server configurations shared by the CLI and the hsloop adapter.

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};

use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, KeyLog, KeyLogFile, RootCertStore, ServerConfig, SupportedProtocolVersion};

use crate::groups;

/// TLS versions for "1.2", "1.3" or "any"
pub fn versions(v: &str) -> Result<&'static [&'static SupportedProtocolVersion], String> {
    static V12: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];
    static V13: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
    static ANY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13, &rustls::version::TLS12];
    match v {
        "1.2" => Ok(V12),
        "1.3" => Ok(V13),
        "any" => Ok(ANY),
        _ => Err(format!("unknown TLS version {v} (1.2, 1.3 or any)")),
    }
}

/// the provider restricted to GROUPS (all of its groups when empty)
pub fn with_groups(p: &CryptoProvider, names: &[&str]) -> Result<Arc<CryptoProvider>, String> {
    let mut p = p.clone();
    if !names.is_empty() {
        p.kx_groups = groups::select(&p.kx_groups, names)?;
    }
    Ok(Arc::new(p))
}

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("{path}: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{path}: no certificates"));
    }
    Ok(certs)
}

pub fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| format!("{path}: {e}"))
}

fn roots(path: &str) -> Result<Arc<RootCertStore>, String> {
    let mut store = RootCertStore::empty();
    for c in load_certs(path)? {
        store.add(c).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(Arc::new(store))
}

/// NSS key log lines written to one file (the servers' --keylog)
#[derive(Debug)]
pub struct FileKeyLog(Mutex<std::fs::File>);

impl FileKeyLog {
    pub fn open(path: &str) -> Result<Self, String> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(|f| Self(Mutex::new(f)))
            .map_err(|e| format!("{path}: {e}"))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Ok(mut f) = self.0.lock() {
            let _ = writeln!(f, "{label} {} {}", hex(client_random), hex(secret));
        }
    }
}

pub struct ClientOpts<'a> {
    pub groups: Vec<&'a str>,
    pub ca: &'a str,
    pub cert_key: Option<(&'a str, &'a str)>,
    pub tls: &'a str,
}

/// A client that verifies the server against CA, offers only GROUPS (key share
/// for the first), never resumes, and logs keys to SSLKEYLOGFILE when it is set.
pub fn client_config(p: &CryptoProvider, o: &ClientOpts) -> Result<ClientConfig, String> {
    let prov = with_groups(p, &o.groups)?;
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(o.ca)?, prov.clone())
        .build()
        .map_err(|e| format!("server verifier: {e}"))?;
    let builder = ClientConfig::builder_with_provider(prov)
        .with_protocol_versions(versions(o.tls)?)
        .map_err(|e| format!("client config: {e}"))?
        .with_webpki_verifier(verifier);
    let mut cfg = match o.cert_key {
        Some((c, k)) => builder
            .with_client_auth_cert(load_certs(c)?, load_key(k)?)
            .map_err(|e| format!("client certificate {c}: {e}"))?,
        None => builder.with_no_client_auth(),
    };
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    if std::env::var_os("SSLKEYLOGFILE").is_some_and(|v| !v.is_empty()) {
        cfg.key_log = Arc::new(KeyLogFile::new());
    }
    Ok(cfg)
}

pub struct ServerOpts<'a> {
    pub groups: Vec<&'a str>,
    pub cert: &'a str,
    pub key: &'a str,
    pub client_ca: Option<&'a str>,
    pub tls: &'a str,
    pub keylog: Option<&'a str>,
}

/// A server with one certificate, accepting only GROUPS, requiring and
/// verifying a client certificate when CLIENT_CA is set. Library defaults
/// otherwise (it sends session tickets, as the other servers do).
pub fn server_config(p: &CryptoProvider, o: &ServerOpts) -> Result<ServerConfig, String> {
    let prov = with_groups(p, &o.groups)?;
    let builder = ServerConfig::builder_with_provider(prov.clone())
        .with_protocol_versions(versions(o.tls)?)
        .map_err(|e| format!("server config: {e}"))?;
    let builder = match o.client_ca {
        Some(ca) => builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(roots(ca)?, prov)
                .build()
                .map_err(|e| format!("client verifier: {e}"))?,
        ),
        None => builder.with_no_client_auth(),
    };
    let mut cfg = builder
        .with_single_cert(load_certs(o.cert)?, load_key(o.key)?)
        .map_err(|e| format!("server certificate {}: {e}", o.cert))?;
    if let Some(path) = o.keylog {
        cfg.key_log = Arc::new(FileKeyLog::open(path)?);
    }
    Ok(cfg)
}
