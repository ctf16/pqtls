//! the crypto provider under test: rustls-rustcrypto (RustCrypto crates; alpha)
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    Provider { name: "rustcrypto", provider: rustls_rustcrypto::provider() }
}
