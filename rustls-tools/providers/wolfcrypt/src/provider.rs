//! the crypto provider under test: rustls-wolfcrypt-provider (wolfCrypt)
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    Provider { name: "wolfcrypt", provider: rustls_wolfcrypt_provider::default_provider() }
}
