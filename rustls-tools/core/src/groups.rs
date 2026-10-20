//! Key-exchange group names: pqcbench.sh uses OpenSSL's TLS group names.

use rustls::crypto::SupportedKxGroup;
use rustls::NamedGroup;

/// (OpenSSL name, TLS NamedGroup code point)
pub const GROUPS: &[(&str, u16)] = &[
    ("X25519", 0x001d),
    ("P-256", 0x0017),
    ("P-384", 0x0018),
    ("P-521", 0x0019),
    ("MLKEM512", 0x0200),
    ("MLKEM768", 0x0201),
    ("MLKEM1024", 0x0202),
    ("SecP256r1MLKEM768", 0x11eb),
    ("X25519MLKEM768", 0x11ec),
    ("SecP384r1MLKEM1024", 0x11ed),
];

/// OpenSSL-style name of a group (rustls's own name for unknown ones)
pub fn name_of(g: NamedGroup) -> String {
    let code = u16::from(g);
    GROUPS
        .iter()
        .find(|(_, c)| *c == code)
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| format!("{g:?}"))
}

fn code_of(name: &str) -> Option<u16> {
    GROUPS
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, c)| *c)
}

/// The provider's groups for a list of OpenSSL names, in that order (the
/// client sends its key share for the first). Fails on a group the provider
/// doesn't implement.
pub fn select(
    available: &[&'static dyn SupportedKxGroup],
    names: &[&str],
) -> Result<Vec<&'static dyn SupportedKxGroup>, String> {
    names
        .iter()
        .map(|n| {
            let code = code_of(n).ok_or_else(|| format!("unknown group {n}"))?;
            available
                .iter()
                .find(|g| u16::from(g.name()) == code)
                .copied()
                .ok_or_else(|| format!("unsupported group {n} (this provider doesn't implement it)"))
        })
        .collect()
}
