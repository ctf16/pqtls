//! the crypto provider under test: rustls-provider-rustcrypto-pq (this project's provider on the current RustCrypto crates, with ML-KEM and ML-DSA)
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    Provider { name: "rustcrypto-pq", provider: rustls_provider_rustcrypto_pq::provider() }
}
