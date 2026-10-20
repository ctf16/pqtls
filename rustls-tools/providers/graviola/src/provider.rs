//! the crypto provider under test: rustls-graviola (graviola: pure Rust, assembly from s2n-bignum)
use pqc_rustls::Provider;

pub fn provider() -> Provider {
    Provider { name: "graviola", provider: rustls_graviola::default_provider() }
}
