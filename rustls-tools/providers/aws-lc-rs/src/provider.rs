//! the crypto provider under test: rustls's aws-lc-rs provider (AWS-LC, bundled
//! by aws-lc-sys), or with the `fips` feature its FIPS module (aws-lc-fips-sys)
use pqc_rustls::Provider;

#[cfg(not(feature = "fips"))]
pub fn provider() -> Provider {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    // every group it implements (the default list leaves out MLKEM768, MLKEM1024)
    p.kx_groups = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS.to_vec();
    Provider { name: "aws-lc-rs", provider: p }
}

#[cfg(feature = "fips")]
pub fn provider() -> Provider {
    let mut p = rustls::crypto::default_fips_provider();
    // every FIPS-approved group it implements, so the provider reports fips()
    p.kx_groups = rustls::crypto::aws_lc_rs::ALL_KX_GROUPS.iter().copied().filter(|g| g.fips()).collect();
    Provider { name: "aws-lc-rs-fips", provider: p }
}
