//! the crypto provider under test: rustls's ring provider
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    let mut p = rustls::crypto::ring::default_provider();
    p.kx_groups = rustls::crypto::ring::ALL_KX_GROUPS.to_vec();
    Provider { name: "ring", provider: p }
}
