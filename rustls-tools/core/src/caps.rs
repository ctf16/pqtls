//! `pqc-rustls caps`: what the provider implements, one item per line
//! (pqcbench.sh decides which pairs rustls can take part in from this).
//!
//!   provider NAME
//!   fips yes|no
//!   group NAME            key-exchange groups, OpenSSL names
//!   version TLSv1.2|TLSv1.3
//!   verify SCHEME         signature schemes it verifies (certificates, CertificateVerify)

use rustls::SignatureScheme;

use crate::{groups, Provider};

pub fn print(p: &Provider) {
    let pr = &p.provider;
    println!("provider {}", p.name);
    println!("fips {}", if pr.fips() { "yes" } else { "no" });
    for g in &pr.kx_groups {
        println!("group {}", groups::name_of(g.name()));
    }
    let (mut v12, mut v13) = (false, false);
    for s in &pr.cipher_suites {
        match s {
            rustls::SupportedCipherSuite::Tls13(_) => v13 = true,
            #[allow(unreachable_patterns)]
            _ => v12 = true,
        }
    }
    if v12 {
        println!("version TLSv1.2");
    }
    if v13 {
        println!("version TLSv1.3");
    }
    let mut seen: Vec<SignatureScheme> = Vec::new();
    for (scheme, _) in pr.signature_verification_algorithms.mapping {
        if !seen.contains(scheme) {
            seen.push(*scheme);
            println!("verify {}", scheme_name(*scheme));
        }
    }
}

/// ML-DSA-65 for the ML-DSA schemes (as pqcbench.sh names them), rustls's
/// name otherwise
pub fn scheme_name(s: SignatureScheme) -> String {
    match u16::from(s) {
        0x0904 => "ML-DSA-44".into(),
        0x0905 => "ML-DSA-65".into(),
        0x0906 => "ML-DSA-87".into(),
        _ => format!("{s:?}"),
    }
}
