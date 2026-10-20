//! pqc-bench rustls tools, generic over a rustls `CryptoProvider`.
//!
//! Each provider crate (providers/<name>) supplies one `CryptoProvider` and
//! gets: the `pqc-rustls` command (`cli::main`: per-process client and server
//! for pqcbench.sh, capability dump, primitive benchmark through the provider
//! interface) and the hsloop adapter (`hsloop_exports!`, linked with
//! hsloop/hsloop.c into hsloop-rustls-<name> for pqcbench.sh --inproc).

pub mod caps;
pub mod cli;
pub mod groups;
pub mod hsloop;
pub mod speed;
pub mod tls;

use rustls::crypto::CryptoProvider;

/// A crypto provider under test: its name (as pqcbench.sh knows it) and the
/// provider with every key-exchange group it implements.
#[derive(Clone)]
pub struct Provider {
    pub name: &'static str,
    pub provider: CryptoProvider,
}
