//! the crypto provider under test: rustls-provider-libcrux-pq (this project's provider on the libcrux crates, with ML-KEM and ML-DSA)
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    Provider { name: "libcrux-pq", provider: rustls_provider_libcrux_pq::provider() }
}
