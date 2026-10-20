//! the crypto provider under test: rustls-provider-graviola-pq (this project's provider on graviola, with ML-KEM-768)
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    Provider { name: "graviola-pq", provider: rustls_provider_graviola_pq::provider() }
}
