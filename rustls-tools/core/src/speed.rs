//! `pqc-rustls speed`: primitive throughput through the provider's rustls
//! interfaces (exactly the code paths a handshake uses), one line per result:
//!
//!   kx GROUP keygen OPS/S encaps OPS/S decaps OPS/S
//!       keygen = client key share (SupportedKxGroup::start); encaps = server
//!       side for one client share (start_and_complete: ML-KEM encapsulation,
//!       or ECDH key generation + agreement); decaps = client side
//!       (ActiveKeyExchange::complete: ML-KEM decapsulation, or ECDH agreement)
//!   sig KEY SCHEME sign OPS/S verify OPS/S
//!       with the PKCS#8 keys in --keys DIR (ecdsa-p256.key, ecdsa-p384.key,
//!       ed25519.key, rsa2048.key, rsa3072.key, mldsa44.key, mldsa65.key,
//!       mldsa87.key; missing files are skipped)
//!   ... unsupported (REASON)   when the provider can't

use std::path::Path;
use std::time::{Duration, Instant};

use rustls::crypto::SupportedKxGroup;
use rustls::SignatureScheme;

use crate::caps::scheme_name;
use crate::{groups, tls, Provider};

/// operations per second of F over about T
fn rate<F: FnMut() -> bool>(t: Duration, mut f: F) -> Option<f64> {
    let start = Instant::now();
    let mut n: u64 = 0;
    loop {
        if !f() {
            return None;
        }
        n += 1;
        let e = start.elapsed();
        if e >= t {
            return Some(n as f64 / e.as_secs_f64());
        }
    }
}

pub fn run(p: &Provider, secs: f64, keys: Option<&str>, do_kx: bool, do_sig: bool) {
    let t = Duration::from_secs_f64(secs);
    println!("provider {}", p.name);
    if do_kx {
        for g in &p.provider.kx_groups {
            kx(*g, t);
        }
    }
    if let (true, Some(dir)) = (do_sig, keys) {
        for (file, label) in KEYS {
            sig(p, &Path::new(dir).join(file), label, t);
        }
    }
}

fn kx(g: &'static dyn SupportedKxGroup, t: Duration) {
    let name = groups::name_of(g.name());
    let Ok(client) = g.start() else {
        println!("kx {name} unsupported (start failed)");
        return;
    };
    let share = client.pub_key().to_vec();
    let keygen = rate(t, || g.start().is_ok());
    let encaps = rate(t, || g.start_and_complete(&share).is_ok());
    // decaps: batches of fresh client keys and server shares; only complete() is timed
    let (mut n, mut spent) = (0u64, Duration::ZERO);
    let mut ok = true;
    while ok && spent < t {
        let mut batch = Vec::with_capacity(32);
        for _ in 0..32 {
            match g.start().and_then(|c| g.start_and_complete(c.pub_key()).map(|s| (c, s.pub_key))) {
                Ok(pair) => batch.push(pair),
                Err(_) => ok = false,
            }
        }
        let t0 = Instant::now();
        for (c, server_share) in batch {
            ok &= c.complete(&server_share).is_ok();
            n += 1;
        }
        spent += t0.elapsed();
    }
    let decaps = (ok && n > 0).then(|| n as f64 / spent.as_secs_f64());
    match (keygen, encaps, decaps) {
        (Some(k), Some(e), Some(d)) => println!("kx {name} keygen {k:.1} encaps {e:.1} decaps {d:.1}"),
        _ => println!("kx {name} unsupported (operation failed)"),
    }
}

const KEYS: &[(&str, &str)] = &[
    ("ecdsa-p256.key", "ECDSA-P256"),
    ("ecdsa-p384.key", "ECDSA-P384"),
    ("ed25519.key", "Ed25519"),
    ("rsa2048.key", "RSA-2048"),
    ("rsa3072.key", "RSA-3072"),
    ("mldsa44.key", "ML-DSA-44"),
    ("mldsa65.key", "ML-DSA-65"),
    ("mldsa87.key", "ML-DSA-87"),
];

/// one DER TLV: (tag, contents, rest)
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&l0, mut b) = b.split_first()?;
    let len = if l0 < 0x80 {
        l0 as usize
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 || b.len() < n {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        b = &b[n..];
        len
    };
    (b.len() >= len).then(|| (tag, &b[..len], &b[len..]))
}

/// SubjectPublicKeyInfo -> (AlgorithmIdentifier contents, public key bits)
fn spki_parts(spki: &[u8]) -> Option<(&[u8], &[u8])> {
    let (0x30, body, _) = tlv(spki)? else { return None };
    let (0x30, alg, rest) = tlv(body)? else { return None };
    let (0x03, bits, _) = tlv(rest)? else { return None };
    Some((alg, bits.get(1..)?))
}

fn sig(p: &Provider, path: &Path, label: &str, t: Duration) {
    if !path.exists() {
        return;
    }
    let key = match tls::load_key(&path.to_string_lossy()) {
        Ok(k) => k,
        Err(e) => return println!("sig {label} unsupported ({e})"),
    };
    let sk = match p.provider.key_provider.load_private_key(key) {
        Ok(k) => k,
        Err(e) => return println!("sig {label} unsupported ({e})"),
    };
    let offer = [
        SignatureScheme::ML_DSA_87,
        SignatureScheme::ML_DSA_65,
        SignatureScheme::ML_DSA_44,
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
    ];
    let Some(signer) = sk.choose_scheme(&offer) else {
        return println!("sig {label} unsupported (no signature scheme for this key)");
    };
    let scheme = signer.scheme();
    let msg = [0x5au8; 64];
    let Ok(signature) = signer.sign(&msg) else {
        return println!("sig {label} unsupported (signing failed)");
    };
    let Some(sign) = rate(t, || signer.sign(&msg).is_ok()) else {
        return println!("sig {label} unsupported (signing failed)");
    };
    // verification as rustls does it: the provider's algorithm for this scheme
    // and the key's SubjectPublicKeyInfo algorithm. The SPKI comes from the
    // signing key, or (providers whose keys don't expose it) from KEY.spki.der
    let spki = sk
        .public_key()
        .map(|s| s.as_ref().to_vec())
        .or_else(|| std::fs::read(path.with_extension("spki.der")).ok());
    let verify = spki.and_then(|spki| {
        let (alg_id, pk) = spki_parts(&spki)?;
        let alg = p
            .provider
            .signature_verification_algorithms
            .mapping
            .iter()
            .find(|(s, _)| *s == scheme)?
            .1
            .iter()
            .find(|a| a.public_key_alg_id().as_ref() == alg_id)?;
        alg.verify_signature(pk, &msg, &signature).ok()?;
        let (pk, sigv) = (pk.to_vec(), signature.clone());
        rate(t, || alg.verify_signature(&pk, &msg, &sigv).is_ok())
    });
    match verify {
        Some(v) => println!("sig {label} {} sign {sign:.1} verify {v:.1}", scheme_name(scheme)),
        None => println!("sig {label} {} sign {sign:.1} verify unsupported", scheme_name(scheme)),
    }
}
