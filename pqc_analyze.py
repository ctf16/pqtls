#!/usr/bin/env python3
"""
pqc_analyze.py - analyse pqcbench.sh results.

Compares, for one or more result runs, OpenSSL, wolfSSL and (when the run has
it) s2n-tls / AWS-LC:

  1. Primitive throughput (keygen, encaps, decaps, sign, verify, agree, ...)
     from `openssl speed`, the wolfCrypt benchmark and AWS-LC's `bssl speed`.

  2. Every TLS client -> server direction for every handshake measurement
     (each key-exchange group and server certificate, and each ML-DSA chain
     profile / issuer): four directions with two libraries, nine with three:
         OpenSSL -> OpenSSL    OpenSSL -> wolfSSL    (OpenSSL -> s2n-tls)
         wolfSSL -> OpenSSL    wolfSSL -> wolfSSL    (wolfSSL -> s2n-tls)
        (s2n-tls -> OpenSSL    s2n-tls -> wolfSSL     s2n-tls -> s2n-tls)
     with medians, spread, ratios against OpenSSL -> OpenSSL (bootstrap 95%
     confidence intervals), and for each pair of libraries a 2x2 breakdown
     into client effect, server effect and cross-implementation ("interop")
     penalty; with several server certificates (pqcbench.sh --cert), what
     each adds over ECDSA P-256 for the same group (cert_costs.csv).

  3. TLS version negotiation and downgrade (pqcbench.sh --versions): the
     outcome of every scenario and direction, and what negotiation, downgrade,
     HelloRetryRequest and refusal cost relative to the reference scenarios,
     with bootstrap 95% confidence intervals. --rtt projects the timings onto a
     network with that round-trip time.

  4. Handshake traffic (pqcbench.sh --capture): for every captured handshake,
     bytes on the wire in each direction, ClientHello and key-share sizes,
     negotiated version/group, HelloRetryRequest and alerts, read straight from
     the pcap/pcapng files (no Wireshark needed), plus connection size by
     key-exchange group and by ML-DSA chain profile.

Usage:
  python3 pqc_analyze.py                      # newest run in ./pqcbench-results
  python3 pqc_analyze.py pqcbench-results/20260928-121751
  python3 pqc_analyze.py RUN1 RUN2 ...        # pool repeated runs
Options:
  --out DIR         where to write CSVs, report.md and charts (default RUN/analysis)
  --bootstrap N     bootstrap resamples for confidence intervals (default 2000, 0 = off)
  --no-plots        skip charts (charts need matplotlib; skipped automatically if missing)
  --all-primitives  also list primitives only one library measured
  --rtt MS          also project version/downgrade timings onto a link with
                    this round-trip time (localhost round trips cost ~0)
  --markdown [FILE] also write a formatted Markdown report (contents, key
                    findings, test setup, embedded charts; default OUT/results.md)

Only the standard library is required; matplotlib is optional (charts).
"""

import argparse
import csv
import html
import math
import os
import random
import re
import statistics
import sys
import textwrap
import time
from collections import OrderedDict, defaultdict

BASE_LIBS = ("openssl", "wolfssl", "s2n")
# register_libs() inserts one rustls_<provider> per rustls crypto provider in the runs
# ("rustls" stays for a run whose env.txt doesn't name its provider)
LIBS = BASE_LIBS + ("rustls",)
LIB_NAME = {"openssl": "OpenSSL", "wolfssl": "wolfSSL", "s2n": "s2n-tls", "awslc": "AWS-LC",
            "rustls": "rustls"}
LIB_SHORT = {"openssl": "O", "wolfssl": "W", "s2n": "S", "rustls": "R"}
RUSTLS_PROVIDERS = ("aws-lc-rs", "ring", "graviola", "graviola-pq", "rustcrypto", "rustcrypto-pq", "libcrux-pq",
                    "wolfcrypt", "aws-lc-rs-fips")
RUSTLS_TAG = {"aws-lc-rs": "a", "ring": "r", "graviola": "g", "graviola-pq": "gp", "rustcrypto": "c",
              "rustcrypto-pq": "cp", "libcrux-pq": "lp", "wolfcrypt": "w", "aws-lc-rs-fips": "f"}
RUSTLS_PROVIDER = {}   # rustls_<provider> -> provider, for the providers in the runs
ALIAS = {}             # run -> {library id in its files: id in the analysis}
# client -> server, in presentation order; set_libraries() derives them from the loaded data
RUN_LIBS = ("openssl", "wolfssl")
DIRECTIONS = [("openssl", "openssl"), ("openssl", "wolfssl"),
              ("wolfssl", "openssl"), ("wolfssl", "wolfssl")]
BASELINE = ("openssl", "openssl")


def rustls_id(provider):
    return "rustls_" + provider.replace("-", "_")


def register_libs(envs):
    """The library ids of the analysis. pqcbench.sh names rustls `rustls` in a run with one
    crypto provider and rustls_<provider> in a run with several; here it is always
    rustls_<provider>, named "rustls (<provider>)", so each provider is a library of its own and
    runs pool by provider. Its provider comes from env.txt's "<id> provider:" line."""
    global LIBS
    found = {}
    for run, env in envs:
        alias = {}
        for l in env.get("libraries", "").split():
            p = env.get(f"{l} provider")
            if l == "rustls" and p:
                alias[l] = rustls_id(p)
                found[alias[l]] = p
            elif l.startswith("rustls_"):
                found[l] = p or l[len("rustls_"):].replace("_", "-")
        ALIAS[run] = alias
    rank = lambda l: (RUSTLS_PROVIDERS.index(found[l]) if found[l] in RUSTLS_PROVIDERS
                      else len(RUSTLS_PROVIDERS), l)
    ids = sorted(found, key=rank)
    for i, l in enumerate(ids):
        RUSTLS_PROVIDER[l] = found[l]
        LIB_NAME[l] = f"rustls ({found[l]})"
        LIB_COLOR[l] = RUSTLS_COLORS[i % len(RUSTLS_COLORS)]
    LIBS = BASE_LIBS + tuple(ids) + ("rustls",)


def canon(run, lib):
    """LIB as the run's files name it -> its id in the analysis (register_libs)."""
    return ALIAS.get(run, {}).get(lib, lib)


def read_rows(run, path):
    """The rows of one of RUN's CSV files, with its client/server library ids made canonical."""
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            for k in ("client", "server"):
                if k in r:
                    r[k] = canon(run, r[k])
            yield r


def lib_env(run, env, lib, field):
    """env.txt's "<id> <field>" line for LIB in RUN (under the id the run gave it), or None."""
    for raw in env.get("libraries", "").split():
        if canon(run, raw) == lib:
            return env.get(f"{raw} {field}")
    return None


def set_libraries(names):
    """Use the libraries named in the data, in LIBS order (OpenSSL + wolfSSL if fewer than two).
    Short labels: R for a lone rustls provider, R + a letter for each of several (Ra, Rr ...)."""
    global RUN_LIBS, DIRECTIONS
    found = tuple(l for l in LIBS if l in names)
    RUN_LIBS = found if len(found) >= 2 else ("openssl", "wolfssl")
    DIRECTIONS = [(c, s) for c in RUN_LIBS for s in RUN_LIBS]
    rl = [l for l in RUN_LIBS if l in RUSTLS_PROVIDER]
    for l in RUSTLS_PROVIDER:
        p = RUSTLS_PROVIDER[l]
        LIB_SHORT[l] = "R" if len(rl) <= 1 else "R" + RUSTLS_TAG.get(p, p[:2])


def own_ratio_label(lib):
    """Column label for LIB's own pair / OpenSSL's: ww/oo, rr/oo; Rgp->Rgp/oo for one of several
    rustls providers (whose short labels share the R)."""
    s = LIB_SHORT.get(lib, lib[0].upper())
    return f"{s.lower() * 2}/oo" if len(s) == 1 else f"{s}->{s}/oo"


def lib_pairs():
    """Library pairs (A, B) for the 2x2 blocks, in LIBS order."""
    return [(a, b) for i, a in enumerate(RUN_LIBS) for b in RUN_LIBS[i + 1:]]


def short_labels():
    return len(DIRECTIONS) > 4


def dir_label(d, full=False):
    if short_labels() and not full:
        return f"{LIB_SHORT[d[0]]}->{LIB_SHORT[d[1]]}"
    return f"{LIB_NAME[d[0]]} -> {LIB_NAME[d[1]]}"


def label_legend(rep):
    """One-line legend for the short direction labels (only printed when they are used)."""
    if short_labels():
        rep.para("Directions are client -> server: "
                 + ", ".join(f"{LIB_SHORT[l]} = {LIB_NAME[l]}" for l in RUN_LIBS) + ".")


# --------------------------------------------------------------------------
# Locating runs
# --------------------------------------------------------------------------
def find_runs(paths):
    if paths:
        runs = []
        for p in paths:
            if not os.path.isdir(p):
                sys.exit(f"error: {p} is not a directory")
            runs.append(os.path.abspath(p))
        return runs
    base = "pqcbench-results"
    if not os.path.isdir(base):
        sys.exit("error: no run directory given and ./pqcbench-results not found")
    subdirs = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
    if not subdirs:
        sys.exit("error: ./pqcbench-results contains no runs")
    return [os.path.abspath(os.path.join(base, subdirs[-1]))]


# --------------------------------------------------------------------------
# Primitive parsing
# --------------------------------------------------------------------------
def _num(tok):
    tok = tok.rstrip("s") if re.fullmatch(r"[\d.]+s", tok) else tok
    try:
        return float(tok)
    except ValueError:
        return None


# OpenSSL speed rate columns -> canonical operation
OSSL_RATE_COLS = {"keygens/s": "keygen", "encaps/s": "encaps", "decaps/s": "decaps",
                  "sign/s": "sign", "verify/s": "verify", "op/s": "agree"}


def canon_openssl_alg(row_name, file_alg):
    n = row_name.strip()
    m = re.search(r"\((X25519|X448|Ed25519|Ed448)\)", n)
    if m:
        return m.group(1)
    m = re.search(r"\(nistp(\d+)\)", n)
    if m:
        return f"P-{m.group(1)}"
    m = re.fullmatch(r"rsa\s*(\d+)(\s+bits)?", n, re.I)
    if m:
        return f"RSA-{m.group(1)}"
    if re.fullmatch(r"[A-Za-z0-9-]+", n):
        return n
    return file_alg


def parse_openssl_speed(path, file_alg):
    """-> {(alg, op): ops_per_sec}; first table wins for duplicates."""
    out = {}
    header = None
    with open(path, errors="replace") as f:
        for line in f:
            toks = line.split()
            if not toks:
                continue
            if any(t.endswith("/s") for t in toks) and all(_num(t) is None for t in toks):
                header = toks
                continue
            if header is None:
                continue
            k = len(header)
            if len(toks) <= k:
                continue
            vals = [_num(t) for t in toks[-k:]]
            if any(v is None for v in vals):
                continue
            alg = canon_openssl_alg(" ".join(toks[:-k]), file_alg)
            if "encaps/s" in header and alg.startswith("RSA-"):
                continue  # RSA-KEM table: nothing comparable in wolfCrypt
            is_rsa_classic = alg.startswith("RSA-") and "encr./s" in header
            for col, val in zip(header, vals):
                op = OSSL_RATE_COLS.get(col)
                if op is None:
                    continue
                if alg.startswith("RSA-") and op in ("sign", "verify"):
                    if not is_rsa_classic and (alg, _rsa_op(op)) in out:
                        continue
                    op = _rsa_op(op)
                out.setdefault((alg, op), val)
    return out


def _rsa_op(op):
    return {"sign": "sign (private)", "verify": "verify (public)"}.get(op, op)


WOLF_LINE = re.compile(
    r"^(?P<name>\S.*?)\s+(?P<op>key gen|encap|decap|sign|verify|agree|public|private)\s+"
    r"\d+\s+ops took .*?(?P<rate>[\d.]+)\s+ops/sec")
WOLF_OPS = {"key gen": "keygen", "encap": "encaps", "decap": "decaps", "sign": "sign",
            "verify": "verify", "agree": "agree",
            "public": "verify (public)", "private": "sign (private)"}
WOLF_CURVES = {"SECP256R1": "P-256", "SECP384R1": "P-384", "SECP521R1": "P-521",
               "SECP224R1": "P-224"}


def canon_wolf_alg(name):
    n = " ".join(name.split())
    m = re.match(r"ML-KEM\s+(\d+)", n)
    if m:
        return f"ML-KEM-{m.group(1)}"
    m = re.match(r"ML-DSA\s+(\d+)", n)
    if m:
        return f"ML-DSA-{m.group(1)}"
    m = re.match(r"(ECC|ECDHE|ECDSA)\s*\[\s*(\S+)\s*\]", n)
    if m:
        return WOLF_CURVES.get(m.group(2).upper(), m.group(2))
    m = re.match(r"CURVE\s+25519", n)
    if m:
        return "X25519"
    m = re.match(r"CURVE\s+448", n)
    if m:
        return "X448"
    m = re.match(r"ED\s+25519", n)
    if m:
        return "Ed25519"
    m = re.match(r"ED\s+448", n)
    if m:
        return "Ed448"
    m = re.match(r"RSA\s+(\d+)", n)
    if m:
        return f"RSA-{m.group(1)}"
    m = re.match(r"DH\s+(\d+)", n)
    if m:
        return f"FFDHE-{m.group(1)}"
    return n


def parse_wolfcrypt(path):
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            m = WOLF_LINE.match(line.strip())
            if not m:
                continue
            key = (canon_wolf_alg(m.group("name")), WOLF_OPS[m.group("op")])
            out.setdefault(key, float(m.group("rate")))
    return out


BSSL_LINE = re.compile(r"^Did \d+ (?P<name>.+?) operations in \d+us \((?P<rate>[\d.]+) ops/sec\)")
BSSL_OPS = {"keygen": "keygen", "encaps": "encaps", "decaps": "decaps", "signing": "sign",
            "verify": "verify", "key generation": "keygen"}


def canon_bssl(name):
    """`bssl speed` benchmark name -> (alg, op), or None for benchmarks not compared."""
    n = " ".join(name.split())
    m = re.fullmatch(r"ML-KEM-(512|768|1024) (keygen|encaps|decaps)", n)
    if m:
        return f"ML-KEM-{m.group(1)}", m.group(2)
    m = re.fullmatch(r"MLDSA(44|65|87) (keygen|signing|verify)", n)
    if m:
        return f"ML-DSA-{m.group(1)}", BSSL_OPS[m.group(2)]
    m = re.fullmatch(r"ECDSA P-(256|384|521) (signing|verify)", n)
    if m:
        return f"P-{m.group(1)}", BSSL_OPS[m.group(2)]
    m = re.fullmatch(r"Ed25519 (key generation|signing|verify)", n)
    if m:
        return "Ed25519", BSSL_OPS[m.group(1)]
    if n == "Curve25519 base-point multiplication":
        return "X25519", "keygen"
    if n == "Curve25519 arbitrary point multiplication":
        return "X25519", "agree"
    m = re.fullmatch(r"EVP ECDH (P-256|P-384|P-521|X25519)", n)
    if m:
        return m.group(1), "keygen+agree"
    m = re.fullmatch(r"RSA (2048|3072) (signing|verify \(same key\))", n)
    if m:
        return f"RSA-{m.group(1)}", "sign (private)" if m.group(2) == "signing" else "verify (public)"
    return None


def parse_bssl_speed(path):
    """AWS-LC `bssl speed` output -> {(alg, op): ops_per_sec}; first occurrence wins."""
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            m = BSSL_LINE.match(line.strip())
            key = canon_bssl(m.group("name")) if m else None
            if key:
                out.setdefault(key, float(m.group("rate")))
    return out


RUSTLS_LINE = re.compile(r"^(kx|sig) (\S+) (.*)$")


def parse_rustls_speed(path):
    """`pqc-rustls speed` output -> {(alg, op): ops_per_sec}. Key exchange runs through the
    provider's rustls interfaces: ML-KEM (and hybrids) keygen/encaps/decaps as they are; for
    ECDH the server side (encaps) is key generation + agreement and the client side (decaps)
    the agreement. Signature keys: ECDSA-P256 -> P-256, RSA-2048 -> RSA-2048 sign (private)."""
    out = {}
    with open(path, errors="replace") as f:
        for line in f:
            m = RUSTLS_LINE.match(line.strip())
            if not m or m.group(3).startswith("unsupported"):
                continue
            kind, name, rest = m.groups()
            toks = rest.split()
            vals = {toks[i]: _num(toks[i + 1]) for i in range(len(toks) - 1) if _num(toks[i + 1]) is not None}
            if kind == "kx":
                alg = name.replace("MLKEM", "ML-KEM-") if re.fullmatch(r"MLKEM\d+", name) else name
                if "MLKEM" in name:
                    ops = {"keygen": "keygen", "encaps": "encaps", "decaps": "decaps"}
                else:
                    ops = {"keygen": "keygen", "encaps": "keygen+agree", "decaps": "agree"}
            else:
                alg = {"ECDSA-P256": "P-256", "ECDSA-P384": "P-384"}.get(name, name)
                ops = ({"sign": "sign (private)", "verify": "verify (public)"} if alg.startswith("RSA-")
                       else {"sign": "sign", "verify": "verify"})
            for k, op in ops.items():
                if vals.get(k):
                    out.setdefault((alg, op), vals[k])
    return out


def load_primitives(runs):
    """-> {(alg, op): {lib: ops_per_sec (median over runs)}}"""
    acc = defaultdict(lambda: defaultdict(list))
    for run in runs:
        pdir = os.path.join(run, "primitives")
        if not os.path.isdir(pdir):
            continue
        for fn in sorted(os.listdir(pdir)):
            path = os.path.join(pdir, fn)
            if fn.startswith("openssl-") and fn.endswith(".txt"):
                vals = parse_openssl_speed(path, fn[len("openssl-"):-4])
                lib = "openssl"
            elif fn.startswith("wolfcrypt") and fn.endswith(".txt"):
                vals = parse_wolfcrypt(path)
                lib = "wolfssl"
            elif fn.startswith("awslc-") and fn.endswith(".txt"):
                vals = parse_bssl_speed(path)
                lib = "awslc"
            elif fn.startswith("rustls") and fn.endswith(("-kem.txt", "-mldsa.txt")):
                # <id>-kem.txt: rustls-kem.txt (one provider), rustls_ring-kem.txt (several)
                vals = parse_rustls_speed(path)
                lib = canon(run, fn[:fn.rindex("-")])
            else:
                continue
            for key, v in vals.items():
                acc[key][lib].append(v)
    return {k: {lib: statistics.median(v) for lib, v in d.items()} for k, d in acc.items()}


# --------------------------------------------------------------------------
# Handshake data
# --------------------------------------------------------------------------
def load_startup(runs):
    vals = defaultdict(list)
    for run in runs:
        ldir = os.path.join(run, "logs")
        for fn in sorted(os.listdir(ldir)) if os.path.isdir(ldir) else []:
            if fn.startswith("startup-") and fn.endswith(".txt"):
                with open(os.path.join(ldir, fn)) as f:
                    vals[canon(run, fn[len("startup-"):-4])] += \
                        [float(x) for x in f.read().split() if _num(x) is not None]
    return {lib: statistics.median(v) for lib, v in vals.items() if v}


# KEM-mode server certificates (pqcbench.sh --cert, --cert-issuer): ec (ECDSA P-256),
# mldsa<level>, mldsa<CA>-<leaf> for a mixed-level ML-DSA chain
KEM_CERT = {}          # key-exchange measurement name -> (group, cert, issuer)


def run_certs(env):
    """-> (KEM server certificates in the run's order, their issuer) from env.txt: "certs:" and
    "cert issuer:", or in runs from before them the one "cert=" (ec if absent; OpenSSL-issued)."""
    return (env.get("certs", "").split() or [env.get("cert", "ec")]), env.get("cert issuer", "openssl")


def cert_label(cert):
    """ec -> ECDSA P-256, mldsa65 -> ML-DSA-65, mldsa87-44 -> ML-DSA-87/ML-DSA-44."""
    if cert == "ec":
        return "ECDSA P-256"
    m = re.fullmatch(r"mldsa(\d+)(?:-(\d+))?", cert)
    return (f"ML-DSA-{m.group(1)}" + (f"/ML-DSA-{m.group(2)}" if m.group(2) else "")) if m else cert


def cert_desc(cert, issuer):
    """Certificate as the report names it: label, plus who issued it unless OpenSSL did."""
    return cert_label(cert) + ("" if issuer == "openssl" else f" ({LIB_NAME.get(issuer, issuer)}-issued)")


def kem_name(group, cert, issuer):
    """Key-exchange measurement name: the group for the default certificate (ECDSA P-256 issued
    by OpenSSL, as before --cert), else "<group>, <certificate> cert", plus " (wolfSSL-issued)"
    for a certificate OpenSSL didn't issue."""
    name = group if (cert, issuer) == ("ec", "openssl") else f"{group}, {cert_label(cert)} cert" \
        + ("" if issuer == "openssl" else f" ({LIB_NAME.get(issuer, issuer)}-issued)")
    KEM_CERT[name] = (group, cert, issuer)
    return name


def cert_order(envs):
    """The runs' certificates in order, ECDSA first."""
    order = ["ec"]
    for _, env in envs:
        order += [c for c in run_certs(env)[0] if c not in order]
    return order


def order_kem(data, envs):
    """DATA with its key-exchange measurements group-major (groups in the order they first
    appear), each group's certificates in the runs' order; other keys stay where they are."""
    kem = [k for k in data if k[0] == "kem"]
    groups = list(dict.fromkeys(KEM_CERT[k[1]][0] for k in kem))
    corder = cert_order(envs)

    def rank(k):
        g, c, iss = KEM_CERT[k[1]]
        return groups.index(g), corder.index(c) if c in corder else len(corder), iss != "openssl", iss
    ordered = iter(sorted(kem, key=rank))
    out = OrderedDict()
    for k in data:
        k = next(ordered) if k[0] == "kem" else k
        out[k] = data[k]
    return out


def cert_pairs(keys):
    """[(measurement, the same group's ECDSA P-256 measurement by the same issuer)] for the
    key-exchange measurements in KEYS with another certificate whose ECDSA one is in KEYS too."""
    names = {k[1] for k in keys if k[0] == "kem"}
    out = []
    for k in keys:
        if k[0] == "kem" and KEM_CERT.get(k[1], ("", "ec"))[1] != "ec":
            g, _, iss = KEM_CERT[k[1]]
            ec = kem_name(g, "ec", iss)
            if ec in names:
                out.append((k[1], ec))
    return out


def load_kem_policies(runs):
    """-> {(key-exchange measurement, client): (policy, extra key share or "")} for the clients
    whose handshakes_summary.csv note names their policy ("(policy default_pq)", and in runs with
    --cert "the policy also sends a P-256 key share")."""
    out = {}
    for run, env in load_env(runs):
        p = os.path.join(run, "handshakes_summary.csv")
        if not os.path.isfile(p):
            continue
        certs, issuer = run_certs(env)
        for r in read_rows(run, p):
            pol = re.search(r"\(policy ([^)\s]+)\)", r.get("note") or "")
            if pol:
                share = re.search(r"also sends an? (\S+) key share", r["note"])
                out[(kem_name(r["group"], r.get("cert") or certs[0], issuer), r["client"])] = \
                    (pol.group(1), share.group(1) if share else "")
    return out


def policy_notes(cells, policies):
    """Notes on client policies that send other key shares with one certificate than with
    another. cells: [(measurement, its ECDSA P-256 measurement or None, clients)]: with an
    ECDSA measurement, where the client's extra key share differs between the two (it skews
    the certificate cost); without, where the client sends an extra key share at all."""
    grouped = OrderedDict()
    for m, ec, clients in cells:
        g, c, iss = KEM_CERT[m]
        for cl in [l for l in LIBS if l in clients] + sorted(set(clients) - set(LIBS)):
            mine, base = policies.get((m, cl)), policies.get((ec, cl)) if ec else None
            if not mine or (ec and (not base or base[1] == mine[1])) or (not ec and not mine[1]):
                continue
            grouped.setdefault((cl, g, mine, base), []).append(cert_desc(c, iss))
    notes = []
    for (cl, g, (pol, share), base), certs in grouped.items():
        names = (", ".join(certs[:-1]) + " and " + certs[-1]) if len(certs) > 1 else certs[0]
        what = (f"{pol}, which also sends a {share} key share" if share
                else f"{pol}, which sends no other key share")
        lead = f"Note: the {LIB_NAME.get(cl, cl)} client's {g} policy with the {names} " \
               f"certificate{'s' if len(certs) > 1 else ''} is {what}"
        if base is None:
            notes.append(lead + " besides the group under test.")
            continue
        effect = (f"includes an extra {share} key share" if not base[1] else
                  f"leaves out a {base[1]} key share" if not share else
                  f"has a {share} key share in place of a {base[1]} one")
        notes.append(lead + f"; with ECDSA P-256 it is {base[0]}, which "
                     + (f"also sends a {base[1]} key share" if base[1] else "sends no other key share")
                     + f". Those {LIB_NAME.get(cl, cl)} client cells' certificate cost {effect}.")
    return notes


def load_handshakes(runs):
    """-> OrderedDict[(suite, measurement)] -> {(client, server): [ms, ...]}"""
    data = OrderedDict()

    def add(key, client, server, ms):
        data.setdefault(key, defaultdict(list))[(client, server)].append(ms)

    envs = load_env(runs)
    for run, env in envs:
        certs, issuer = run_certs(env)
        p = os.path.join(run, "handshakes_raw.csv")
        if os.path.isfile(p):
            for r in read_rows(run, p):
                add(("kem", kem_name(r["group"], r.get("cert") or certs[0], issuer)),
                    r["client"], r["server"], float(r["ms"]))
        p = os.path.join(run, "mldsa_handshakes_raw.csv")
        if os.path.isfile(p):
            main_group = mldsa_group([run])
            for r in read_rows(run, p):
                name = f"ML-DSA {r['profile']} ({LIB_NAME.get(r['producer'], r['producer'])} chain)"
                # pairs that used another key exchange (pqcbench.sh --pure-pq fallbacks)
                # are a measurement of their own
                if r.get("group") and r["group"] != main_group:
                    name += f" via {r['group']}"
                add(("mldsa", name), r["client"], r["server"], float(r["ms"]))
    return order_kem(data, envs)


def mldsa_group(runs):
    for run in runs:
        p = os.path.join(run, "env.txt")
        if os.path.isfile(p):
            with open(p) as f:
                m = re.search(r"mldsa profiles:.*group:\s*(\S+)", f.read())
                if m:
                    return m.group(1)
    return "?"


def load_env(runs):
    """-> [(run, OrderedDict setting -> value)] from each run's env.txt."""
    out = []
    for run in runs:
        env = OrderedDict()
        p = os.path.join(run, "env.txt")
        if os.path.isfile(p):
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        env[k] = v.strip()
                    else:                        # "iterations=100 mldsa_iterations=20 ..."
                        for tok in line.split():
                            if "=" in tok:
                                k, v = tok.split("=", 1)
                                env[k] = v
        out.append((run, env))
    return out


def awslc_entropy(envs, lib="s2n"):
    """'jitter', 'nojitter' or 'mixed': AWS-LC entropy builds in the runs that tested LIB
    (s2n-tls's AWS-LC, or the AWS-LC in a rustls_<provider>'s aws-lc-rs provider). Runs from
    before env.txt recorded it ran the stock (CPU-jitter) build; other rustls providers have
    no AWS-LC (None)."""
    kinds = set()
    for run, env in envs:
        if lib not in (canon(run, l) for l in env.get("libraries", "").split()):
            continue
        v = env.get("aws-lc entropy", "") if lib == "s2n" else lib_env(run, env, lib, "aws-lc entropy")
        if v is not None:
            kinds.add("nojitter" if "without CPU jitter" in v else "jitter")
    return kinds.pop() if len(kinds) == 1 else "mixed" if kinds else None


def fips_mode(envs):
    """'on', 'off' or 'mixed': pqcbench.sh --fips runs (FIPS builds, approved algorithms only).
    Runs from before env.txt recorded it weren't FIPS runs."""
    kinds = {env.get("fips", "off") for _, env in envs}
    return kinds.pop() if len(kinds) == 1 else "mixed" if kinds else None


def netsim_settings(envs):
    """-> ("off" | "on" | "mixed", settings): pqcbench.sh --mtu/--rtt/--bw runs, from env.txt's
    "netsim:" line (runs from before it recorded one had none). settings (for "on"): line (the
    env.txt line without the watchdog), mtu, rtt (requested ms), measured (ms: mean of the RTTs
    measured at the start and, in "netsim end:", the end of each run; or None), bw. Runs with the
    same mtu, rtt and bw pool; others are "mixed"."""
    def parse(line):
        def num(pat):
            m = re.search(pat, line)
            return float(m.group(1)) if m else None
        bw = re.search(r"bw ([^,]+),", line)
        return {"line": re.sub(r", watchdog \d+$", "", line), "mtu": num(r"mtu (\d+)"),
                "rtt": num(r"rtt ([\d.]+) ms") or 0.0, "measured": num(r"measured ([\d.]+) ms"),
                "bw": bw.group(1) if bw else "unlimited"}
    lines = [env.get("netsim", "off") for _, env in envs]
    if all(l == "off" for l in lines):
        return "off", None
    if any(l == "off" for l in lines):
        return "mixed", None
    parsed = [parse(l) for l in lines]
    if len({(p["mtu"], p["rtt"], p["bw"]) for p in parsed}) > 1:
        return "mixed", None
    s = dict(parsed[0])
    meas = [p["measured"] for p in parsed if p["measured"] is not None]
    meas += [float(m.group(1)) for _, env in envs
             for m in [re.search(r"measured ([\d.]+) ms", env.get("netsim end", ""))] if m]
    s["measured"] = statistics.mean(meas) if meas else None
    return "on", s


def remote_settings(envs):
    """-> ("off" | "on" | "mixed", settings): pqcbench.sh --remote runs (servers on another host),
    from env.txt's "remote:" line. settings (for "on"): line (the servers and the address the
    clients used), measured (ms: mean of the round trips measured at the start and, in
    "remote end:", the end of each run; or None), what and path (analyse_round_trips' wording).
    Runs against the same servers pool; others, or a mix with local runs, are "mixed"."""
    lines = [env.get("remote") for _, env in envs]
    if all(l is None for l in lines):
        return "off", None
    where = {re.sub(r";.*", "", l) for l in lines if l is not None}
    if any(l is None for l in lines) or len(where) > 1:
        return "mixed", None
    meas = [float(m.group(1)) for _, env in envs for k in ("remote", "remote end")
            for m in [re.search(r"measured ([\d.]+) ms", env.get(k, ""))] if m]
    return "on", {"line": where.pop(), "measured": statistics.mean(meas) if meas else None,
                  "what": "Remote servers", "path": "the network path"}


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------
def quantile(sorted_xs, q):
    if not sorted_xs:
        return float("nan")
    pos = (len(sorted_xs) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * (pos - lo)


def describe(xs):
    s = sorted(xs)
    return {"n": len(s), "median": quantile(s, 0.5), "p25": quantile(s, 0.25),
            "p75": quantile(s, 0.75), "p95": quantile(s, 0.95),
            "min": s[0] if s else float("nan"), "max": s[-1] if s else float("nan")}


def complete_blocks(present):
    """Library pairs (A, B) whose 2x2 cells AA, AB, BA, BB are all in `present`."""
    return [(a, b) for a, b in lib_pairs()
            if all(d in present for d in ((a, a), (a, b), (b, a), (b, b)))]


def cell_statistics(meds, blocks):
    """meds: {direction: median} -> derived statistics, keyed
    ("ratio", direction) for time vs OpenSSL -> OpenSSL (only with a complete block) and
    (statistic, (A, B)) for each complete 2x2 block (effects = swapping A for B, in ms)."""
    out = {}
    oo = meds.get(BASELINE)
    if oo is not None and blocks:
        for d in DIRECTIONS:
            if d != BASELINE and d in meds:
                out[("ratio", d)] = meds[d] / oo
    for a, b in blocks:
        aa, ab, ba, bb = meds[(a, a)], meds[(a, b)], meds[(b, a)], meds[(b, b)]
        # 2x2 decomposition (ms); negative = the B side faster
        out[("client_effect", (a, b))] = ((ba + bb) - (aa + ab)) / 2
        out[("server_effect", (a, b))] = ((ab + bb) - (aa + ba)) / 2
        # extra cost of mixed pairs over what the additive model predicts
        out[("interop_penalty", (a, b))] = ((ab + ba) - (aa + bb)) / 2
    return out


def _stat_cells(key):
    if key[0] == "ratio":
        return (BASELINE, key[1])
    a, b = key[1]
    return ((a, a), (a, b), (b, a), (b, b))


def bootstrap(samples, B, seed=1):
    """Percentile 95% CIs for cell_statistics, one joint resample of every cell with >= 2
    samples per iteration; statistics using a cell with fewer samples get no CI."""
    present = [d for d in DIRECTIONS if samples.get(d)]
    blocks = complete_blocks(present)
    if B <= 0 or not blocks:
        return {}
    fixed = {d: statistics.median(samples[d]) for d in present if len(samples[d]) < 2}
    rng = random.Random(seed)
    draws = defaultdict(list)
    for _ in range(B):
        meds = dict(fixed)
        for d in present:
            if d not in fixed:
                meds[d] = statistics.median(rng.choices(samples[d], k=len(samples[d])))
        for k, v in cell_statistics(meds, blocks).items():
            draws[k].append(v)
    return {k: (quantile(sorted(v), 0.025), quantile(sorted(v), 0.975)) for k, v in draws.items()
            if not any(d in fixed for d in _stat_cells(k))}


def geomean(xs):
    xs = [x for x in xs if x and x > 0 and not math.isnan(x)]
    return math.exp(sum(math.log(x) for x in xs) / len(xs)) if xs else float("nan")


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------
class Strong(str):
    """Table cell shown in bold in the formatted Markdown report (plain everywhere else)."""


class Report:
    """Collects sections; prints them to the terminal and writes report.md.

    It also records every call as a block for the formatted report (--markdown). Hints that
    only the formatted report uses: Strong cells, para(note=True) (call-out), finding=True
    (also listed under "At a glance"), table(collapse=True) (folded into <details>; a
    directly preceding plain paragraph ending in ':' becomes the summary line) and chart().
    """

    def __init__(self):
        self.md = []
        self.blocks = []
        self.findings = []           # (level-2 section title, block)
        self._section = None

    def heading(self, text, level=2):
        print(f"\n== {text} ==" if level == 2 else f"\n{text}")
        self.md.append(f"\n{'#' * level} {text}\n")
        self.blocks.append(("heading", level, text))
        if level == 2:
            self._section = text

    def para(self, text, note=False, finding=False):
        print(text)
        self.md.append(text + "\n")
        blk = ("note" if note else "para", text.strip("\n"))
        self.blocks.append(blk)
        if finding:
            self.findings.append((self._section, blk))

    def bullets(self, items):
        for it in items:
            print(f"  - {it}")
            self.md.append(f"- {it}")
        self.md.append("")
        self.blocks.append(("bullets", list(items)))

    def table(self, header, rows, align=None, collapse=False, finding=False):
        cols = len(header)
        align = align or ["l"] + ["r"] * (cols - 1)
        cells = [header] + [[str(c) for c in r] for r in rows]
        w = [max(len(r[i]) for r in cells) for i in range(cols)]
        for r in cells:
            print("  " + "  ".join(c.ljust(w[i]) if align[i] == "l" else c.rjust(w[i])
                                   for i, c in enumerate(r)).rstrip())
        sep = ["---" if a == "l" else "---:" for a in align]
        self.md.append("| " + " | ".join(header) + " |")
        self.md.append("| " + " | ".join(sep) + " |")
        for r in cells[1:]:
            self.md.append("| " + " | ".join(r) + " |")
        self.md.append("")
        blk = ("table", list(header), [list(r) for r in rows], align, collapse)
        self.blocks.append(blk)
        if finding:
            self.findings.append((self._section, blk))

    def chart(self, filename, alt):
        """Slot for a chart; the formatted report embeds it if the chart was drawn."""
        self.blocks.append(("chart", filename, alt))

    def write(self, path, title):
        with open(path, "w") as f:
            f.write(f"# {title}\n" + "\n".join(self.md) + "\n")

    def write_markdown(self, path, title, envs, charts, settings):
        """Formatted report: contents, key findings, test setup, sections with charts.
        envs: load_env() output; charts: paths drawn this run; settings: [(name, value)]."""
        base = os.path.dirname(os.path.abspath(path))
        os.makedirs(base, exist_ok=True)
        drawn = {os.path.basename(c): c for c in charts}
        slugs = defaultdict(int)

        def anchor(text):                # GitHub heading ids, with -1, -2 ... for repeats
            s = re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")
            slugs[s] += 1
            return s if slugs[s] == 1 else f"{s}-{slugs[s] - 1}"

        out = [f"# {title}", "",
               f"Generated {time.strftime('%Y-%m-%d %H:%M')} by `pqc_analyze.py` from "
               + ", ".join(f"`{os.path.basename(r)}`" for r, _ in envs) + "."
               + (" Samples from all runs are pooled." if len(envs) > 1 else ""), "",
               "## Contents", ""]
        anchor("Contents")
        for text, level in [("At a glance", 2), ("Test setup", 2)] + \
                [(_pretty(b[2]), b[1]) for b in self.blocks if b[0] == "heading"]:
            out.append(f"{'  ' * (level - 2)}- [{text}](#{anchor(text)})")
        out += ["", "## At a glance", ""]
        section = object()
        for sec, blk in self.findings:
            if sec != section:
                out += [f"**{_pretty(re.sub(r'^[0-9]+[.] ', '', sec or ''))}**", ""]
                section = sec
            out += _render_block(blk, base, drawn)
        if not self.findings:
            out += ["No results to summarise.", ""]

        out += ["## Test setup", ""]
        keys = []
        for _, env in envs:
            keys += [k for k in env if k not in keys]
        rows = [[k] + [env.get(k, "-") for _, env in envs] for k in keys]

        def kem_certs(env):              # env.txt "certs:"/"cert issuer:", or the older "cert="
            if "kem" not in (env.get("modes") or "kem").split()[0].split("+"):
                return "-"
            certs, issuer = run_certs(env)
            return ", ".join(cert_label(c) for c in certs) + f" (issued by {LIB_NAME.get(issuer, issuer)})"
        rows.append(["key-exchange server certificates"] + [kem_certs(env) for _, env in envs])
        rows += [[k] + [v] * len(envs) for k, v in settings]
        out += _md_table(["setting"] + [os.path.basename(r) for r, _ in envs], rows,
                         ["l"] * (len(envs) + 1))

        # the preamble before the first heading (the run list) is covered by Test setup
        first = next((i for i, b in enumerate(self.blocks) if b[0] == "heading"), len(self.blocks))
        prev = None
        for blk in self.blocks[first:]:
            if blk[0] == "heading" and blk[1] == 2:
                out += ["---", ""]
            if blk[0] == "table" and blk[4] and prev and prev[0] == "para" \
                    and prev[1].endswith(":") and "\n" not in prev[1]:
                out = out[:-2]           # the intro paragraph becomes the <details> summary
                out += _render_block(blk, base, drawn, summary=prev[1].rstrip(":"))
            else:
                out += _render_block(blk, base, drawn)
            prev = blk
        with open(path, "w") as f:
            f.write("\n".join(out).rstrip("\n") + "\n")


def _pretty(text):
    return (text.replace(" -> ", " → ").replace("->", "→").replace("us/op", "µs/op")
            .replace("2x2", "2×2"))


def _md_cell(c):
    s = _pretty(str(c)).replace("|", "\\|").replace("*", "\\*")
    return f"**{s}**" if isinstance(c, Strong) and s not in ("", "-") else s


def _md_table(header, rows, align):
    sep = [":---" if a == "l" else "---:" for a in align]
    lines = ["| " + " | ".join(_md_cell(h) for h in header) + " |", "| " + " | ".join(sep) + " |"]
    lines += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in rows]
    return lines + [""]


def _render_block(blk, base, drawn, summary=None):
    kind = blk[0]
    if kind == "heading":
        return [f"{'#' * blk[1]} {_pretty(blk[2])}", ""]
    if kind == "para":
        return [_pretty(blk[1]), ""]
    if kind == "note":
        return ["> " + line if line else ">" for line in _pretty(blk[1]).split("\n")] + [""]
    if kind == "bullets":
        return [f"- {_pretty(it)}" for it in blk[1]] + [""]
    if kind == "chart":
        if blk[1] not in drawn:
            return []
        return [f"![{blk[2]}]({os.path.relpath(drawn[blk[1]], base)})", ""]
    _, header, rows, align, collapse = blk
    table = _md_table(header, rows, align)
    if not collapse:
        return table
    summary = html.escape(_pretty(summary) if summary else f"Show table ({len(rows)} rows)")
    return ["<details>", f"<summary>{summary}</summary>", ""] + table + ["</details>", ""]


def fmt(x, nd=2):
    return "-" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def fmt_rate(x):
    if x is None:
        return "-"
    return f"{x:,.0f}" if x >= 100 else f"{x:,.1f}"


def fmt_ci(ci, nd=2):
    return f"[{ci[0]:.{nd}f}, {ci[1]:.{nd}f}]" if ci else ""


# --------------------------------------------------------------------------
# Analyses
# --------------------------------------------------------------------------
ALG_ORDER = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768",
             "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "ML-DSA-44", "ML-DSA-65",
             "ML-DSA-87", "X25519", "X448", "P-256", "P-384", "P-521", "Ed25519", "Ed448",
             "RSA-2048", "RSA-3072"]
OP_ORDER = ["keygen", "encaps", "decaps", "sign", "verify", "agree", "keygen+agree",
            "sign (private)", "verify (public)"]


def sort_key(key):
    alg, op = key
    a = ALG_ORDER.index(alg) if alg in ALG_ORDER else len(ALG_ORDER)
    o = OP_ORDER.index(op) if op in OP_ORDER else len(OP_ORDER)
    return (a, alg, o, op)


def _family(alg):
    return ("ML-KEM" if alg.startswith("ML-KEM") else "ML-DSA" if alg.startswith("ML-DSA")
            else "RSA" if alg.startswith("RSA") else "EC/DH")


def prim_libs():
    """Libraries the primitive benchmarks can come from: OpenSSL, wolfCrypt, AWS-LC (bssl)
    and every rustls provider (pqc-rustls speed)."""
    return ("openssl", "wolfssl", "awslc") + tuple(l for l in LIBS if l.startswith("rustls"))


def analyse_primitives(prims, rep, outdir, show_all):
    """-> {lib: [(key, openssl ops/s, lib ops/s, ratio)]} for wolfSSL (and AWS-LC, rustls if measured)."""
    if any(l not in ("openssl", "wolfssl") for v in prims.values() for l in v):
        return _analyse_primitives3(prims, rep, outdir, show_all)
    return {"wolfssl": _analyse_primitives2(prims, rep, outdir, show_all)}


def _analyse_primitives3(prims, rep, outdir, show_all):
    """OpenSSL against every other library measured (wolfSSL, AWS-LC, rustls's providers)."""
    libs = [l for l in prim_libs() if any(l in v for v in prims.values())]
    rustls = [l for l in libs if l.startswith("rustls")]
    others = [l for l in libs if l != "openssl"]
    rows_csv, table = [], []
    paired = {l: [] for l in others}
    for key in sorted(prims, key=sort_key):
        rate = {l: prims[key].get(l) for l in libs}
        o, w = rate.get("openssl"), rate.get("wolfssl")
        ratio = {l: (rate[l] / o) if (o and rate[l]) else None for l in others}
        rw = ratio.get("wolfssl")
        if rw is None:
            faster = "only " + ("OpenSSL" if o else "wolfSSL") if (o or w) else ""
        else:
            faster = "wolfSSL" if rw >= 1.05 else "OpenSSL" if rw <= 1 / 1.05 else "~ same"
        have = sorted((v, l) for l, v in rate.items() if v)
        if len(have) == 1:
            fastest = "only " + LIB_NAME[have[0][1]]
        elif have[-1][0] >= 1.05 * have[-2][0]:
            fastest = LIB_NAME[have[-1][1]]
        else:
            fastest = "~ same"
        lead = have[-1][0] / have[-2][0] if len(have) >= 2 else None
        us = {l: f"{1e6 / v:.3f}" if v else "" for l, v in rate.items()}
        rr = lambda l: f"{ratio[l]:.4f}" if ratio.get(l) else ""
        row = [key[0], key[1], o or "", w or "", us.get("openssl", ""), us.get("wolfssl", ""),
               rr("wolfssl"), faster, rate.get("awslc") or "", us.get("awslc", ""), rr("awslc"), fastest]
        for l in rustls:
            row += [rate[l] or "", us[l], rr(l)]
        rows_csv.append(row)
        for l in others:
            if ratio[l] is not None:
                paired[l].append((key, o, rate[l], ratio[l]))
        if len(have) >= 2 or show_all:
            S = lambda lib, txt: Strong(txt) if fastest == LIB_NAME[lib] else txt
            table.append([key[0], key[1]] + [S(l, fmt_rate(rate[l])) for l in libs]
                         + [S(l, fmt(1e6 / rate[l], 1) if rate[l] else "-") for l in libs]
                         + [f"{ratio[l]:.2f}x" if ratio[l] else "-" for l in others]
                         + [fastest, f"{lead:.2f}x" if lead else "-"])

    with open(os.path.join(outdir, "primitives_comparison.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        head = ["algorithm", "operation", "openssl_ops_per_s", "wolfssl_ops_per_s",
                "openssl_us_per_op", "wolfssl_us_per_op", "ratio_wolfssl_over_openssl",
                "faster", "awslc_ops_per_s", "awslc_us_per_op", "ratio_awslc_over_openssl",
                "fastest"]
        for l in rustls:
            head += [f"{l}_ops_per_s", f"{l}_us_per_op", f"ratio_{l}_over_openssl"]
        wr.writerow(head)
        wr.writerows(rows_csv)

    names = [LIB_NAME[l] for l in libs]
    # several rustls providers: "rustls (aws-lc-rs, ring)"
    title = [LIB_NAME[l] for l in libs if l not in rustls] + (
        [LIB_NAME[rustls[0]]] if len(rustls) == 1 else
        [f"rustls ({', '.join(RUSTLS_PROVIDER.get(l, l) for l in rustls)})"] if rustls else [])
    rep.heading("1. Primitives: " + ", ".join(title[:-1]) + " and " + title[-1])
    rep.para("ratio = library ops/s / OpenSSL ops/s  (>1 means that library is faster); fastest = "
             "highest throughput if at least 5% ahead of the runner-up; lead = fastest ops/s / "
             "second-fastest ops/s", note=True)
    rep.chart("primitives_ratio.png", "Primitive throughput ratio vs OpenSSL")
    rep.table(["algorithm", "op"] + [f"{n} ops/s" for n in names] + [f"{n} us/op" for n in names]
              + [f"{LIB_NAME[l]}/OpenSSL" for l in others] + ["fastest", "lead"],
              table, ["l", "l"] + ["r"] * (2 * len(libs) + len(others)) + ["l", "r"])
    fams = OrderedDict()
    for lib in others:
        pl = paired[lib]
        if not pl:
            continue
        name = LIB_NAME[lib]
        wins = defaultdict(int)
        for (_, _, _, r) in pl:
            wins[name if r >= 1.05 else "OpenSSL" if r <= 1 / 1.05 else "same"] += 1
        g = geomean([p[3] for p in pl])
        rep.para(f"\n{name} faster in {wins[name]}, OpenSSL faster in {wins['OpenSSL']}, "
                 f"within 5% in {wins['same']} of {len(pl)} comparable operations. "
                 f"Geometric mean ratio: {g:.2f}x "
                 f"({name if g > 1 else 'OpenSSL'} ahead overall).", finding=True)
        for (alg, _), _, _, r in pl:
            fams.setdefault(_family(alg), defaultdict(list))[lib].append(r)
    libs_p = [l for l in others if paired[l]]
    if libs_p:
        rep.table(["family"] + [f"{LIB_NAME[l]}/OpenSSL geo-mean (ops)" for l in libs_p],
                  [[fam] + [f"{geomean(d[l]):.2f}x ({len(d[l])})" if d[l] else "-" for l in libs_p]
                   for fam, d in fams.items()], finding=True)
    rep.para("RSA: wolfCrypt reports raw private/public operations, compared here with "
             "OpenSSL sign/verify. `openssl speed` ECDH 'op' is compared with wolfCrypt 'agree'. "
             "AWS-LC (`bssl speed`): X25519 agree is Curve25519 arbitrary-point multiplication "
             "(keygen is base-point multiplication); its ECDH benchmarks include key generation, "
             "so they are listed as keygen+agree and not compared; RSA = signing / verify (same key)."
             + (" rustls (`pqc-rustls speed`) measures through the provider's rustls interfaces: "
                "keygen = a client key share, encaps = the server side for one share (for ECDH: "
                "key generation + agreement, listed as keygen+agree), decaps = the client side "
                "(for ECDH: agreement, listed as agree); RSA signs with RSA-PSS-SHA256."
                if rustls else ""),
             note=True)
    return paired


def _analyse_primitives2(prims, rep, outdir, show_all):
    rows_csv, table, paired = [], [], []
    for key in sorted(prims, key=sort_key):
        o, w = prims[key].get("openssl"), prims[key].get("wolfssl")
        ratio = (w / o) if (o and w) else None
        if ratio is None:
            winner = "only " + ("OpenSSL" if o else "wolfSSL")
        elif ratio >= 1.05:
            winner = "wolfSSL"
        elif ratio <= 1 / 1.05:
            winner = "OpenSSL"
        else:
            winner = "~ same"
        rows_csv.append([key[0], key[1], o or "", w or "",
                         f"{1e6 / o:.3f}" if o else "", f"{1e6 / w:.3f}" if w else "",
                         f"{ratio:.4f}" if ratio else "", winner])
        if ratio is not None:
            paired.append((key, o, w, ratio))
        if ratio is not None or show_all:
            S = lambda lib, txt: Strong(txt) if winner == lib else txt
            table.append([key[0], key[1], S("OpenSSL", fmt_rate(o)), S("wolfSSL", fmt_rate(w)),
                          S("OpenSSL", fmt(1e6 / o, 1) if o else "-"),
                          S("wolfSSL", fmt(1e6 / w, 1) if w else "-"),
                          (f"{ratio:.2f}x" if ratio else "-"), winner,
                          (f"{max(ratio, 1 / ratio):.2f}x" if ratio else "-")])

    with open(os.path.join(outdir, "primitives_comparison.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["algorithm", "operation", "openssl_ops_per_s", "wolfssl_ops_per_s",
                     "openssl_us_per_op", "wolfssl_us_per_op", "ratio_wolfssl_over_openssl",
                     "faster"])
        wr.writerows(rows_csv)

    rep.heading("1. Primitives: OpenSSL vs wolfSSL")
    if not table:
        rep.para("No primitive results found (run pqcbench.sh without --handshakes-only).")
        return paired
    rep.para("ratio = wolfSSL ops/s / OpenSSL ops/s  (>1 means wolfSSL is faster); "
             "lead = faster ops/s / slower ops/s", note=True)
    rep.chart("primitives_ratio.png", "Primitive throughput ratio, wolfSSL vs OpenSSL")
    rep.table(["algorithm", "op", "OpenSSL ops/s", "wolfSSL ops/s", "OpenSSL us/op",
               "wolfSSL us/op", "ratio", "faster", "lead"], table,
              ["l", "l", "r", "r", "r", "r", "r", "l", "r"])
    if paired:
        wins = defaultdict(int)
        for (_, _, _, r) in paired:
            wins["wolfSSL" if r >= 1.05 else "OpenSSL" if r <= 1 / 1.05 else "same"] += 1
        g = geomean([p[3] for p in paired])
        rep.para(f"\nwolfSSL faster in {wins['wolfSSL']}, OpenSSL faster in {wins['OpenSSL']}, "
                 f"within 5% in {wins['same']} of {len(paired)} comparable operations. "
                 f"Geometric mean ratio: {g:.2f}x "
                 f"({'wolfSSL' if g > 1 else 'OpenSSL'} ahead overall).", finding=True)
        byfam = defaultdict(list)
        for (alg, _), _, _, r in paired:
            byfam[_family(alg)].append(r)
        rep.table(["family", "comparable ops", "geo-mean ratio"],
                  [[k, len(v), f"{geomean(v):.2f}x"] for k, v in byfam.items()], finding=True)
    rep.para("RSA: wolfCrypt reports raw private/public operations, compared here with "
             "OpenSSL sign/verify. `openssl speed` ECDH 'op' is compared with wolfCrypt 'agree'.",
             note=True)
    return paired


def analyse_handshakes(hs, startup, B, rep, outdir, group, entropy, policies):
    results = OrderedDict()  # key -> dict
    for key, cells in hs.items():
        desc = {d: describe(cells[d]) for d in DIRECTIONS if cells.get(d)}
        blocks = complete_blocks(desc)
        stats = cell_statistics({d: s["median"] for d, s in desc.items()}, blocks)
        results[key] = {"desc": desc, "stats": stats, "blocks": blocks,
                        "ratios": BASELINE in desc and bool(blocks),
                        "ci": bootstrap(cells, B) if blocks else {},
                        "complete": len(desc) == len(DIRECTIONS)}
    dstart = lambda a, b: (startup[b] - startup[a]) if a in startup and b in startup else None

    # CSV: one row per measurement x direction
    with open(os.path.join(outdir, "handshake_directions.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["suite", "measurement", "client", "server", "n", "median_ms", "p25_ms",
                     "p75_ms", "p95_ms", "min_ms", "max_ms", "adj_median_ms",
                     "ratio_vs_openssl_openssl", "ratio_ci_low", "ratio_ci_high"])
        for (suite, meas), r in results.items():
            for d in DIRECTIONS:
                if d not in r["desc"]:
                    continue
                s = r["desc"][d]
                ratio = (1.0 if d == BASELINE else r["stats"][("ratio", d)]) if r["ratios"] else ""
                ci = r["ci"].get(("ratio", d), ("", ""))
                adj = s["median"] - startup[d[0]] if d[0] in startup else ""
                wr.writerow([suite, meas, d[0], d[1], s["n"]] +
                            [f"{s[k]:.3f}" for k in ("median", "p25", "p75", "p95", "min", "max")] +
                            [f"{adj:.3f}" if adj != "" else "", ratio if ratio == "" else f"{ratio:.4f}",
                             ci[0] if ci[0] == "" else f"{ci[0]:.4f}",
                             ci[1] if ci[1] == "" else f"{ci[1]:.4f}"])

    with open(os.path.join(outdir, "handshake_effects.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["suite", "measurement", "client_effect_ms", "client_effect_excl_startup_ms",
                     "server_effect_ms", "interop_penalty_ms", "client_ci_low", "client_ci_high",
                     "server_ci_low", "server_ci_high", "interop_ci_low", "interop_ci_high",
                     "library_a", "library_b"])
        for (suite, meas), r in results.items():
            for p in r["blocks"]:
                st, ci, ds = r["stats"], r["ci"], dstart(*p)
                row = [suite, meas, f"{st[('client_effect', p)]:.3f}",
                       f"{st[('client_effect', p)] - ds:.3f}" if ds is not None else "",
                       f"{st[('server_effect', p)]:.3f}", f"{st[('interop_penalty', p)]:.3f}"]
                for k in ("client_effect", "server_effect", "interop_penalty"):
                    row += [f"{ci[(k, p)][0]:.3f}", f"{ci[(k, p)][1]:.3f}"] if (k, p) in ci else ["", ""]
                wr.writerow(row + list(p))

    rep.heading("2. Handshakes: client -> server direction")
    if not results:
        rep.para("No handshake results found.")
        return results
    if startup:
        s2n_note = {
            "jitter": " (s2n-tls's includes library init: s2n_init seeds AWS-LC's CPU-jitter entropy "
                      "source; that busy loop also slows s2nc's process start and exit in some runs, "
                      "so its 'client excl. startup' figures overstate the handshake)",
            "nojitter": " (s2n-tls's includes library init; AWS-LC built without CPU-jitter entropy, "
                        "seeded from the OS)",
            "mixed": " (s2n-tls's includes library init; the pooled runs mix AWS-LC builds with and "
                     "without CPU-jitter entropy, see Test setup)",
        }.get(entropy.get("s2n"), "")
        def rustls_note(l):
            return {
                "jitter": f" ({LIB_NAME[l]}'s includes the provider's set-up, which seeds AWS-LC's "
                          "CPU-jitter entropy source; that busy loop makes its process times vary by a "
                          "few ms with what ran before it (more after s2n-tls's clients), so its "
                          "'client excl. startup' figures are rough and can come out negative)",
                "nojitter": f" ({LIB_NAME[l]}'s includes the provider's set-up; its AWS-LC built "
                            "without CPU-jitter entropy, seeded from the OS)",
                "mixed": f" ({LIB_NAME[l]}: the pooled runs mix AWS-LC builds with and without "
                         "CPU-jitter entropy, see Test setup)",
            }.get(entropy.get(l), "")
        rep.para("Process startup baseline (median): " +
                 ", ".join(f"{LIB_NAME[l]} client {startup[l]:.2f} ms" for l in LIBS if l in startup)
                 + (s2n_note if "s2n" in startup else "")
                 + "".join(rustls_note(l) for l in RUSTLS_PROVIDER if l in startup))

    pairs = lib_pairs()
    two = len(pairs) == 1
    others = RUN_LIBS[1:]
    legend_done = bullets_done = False
    for suite, title in (("kem", "Key exchange (server certificate ECDSA P-256 unless the measurement "
                                 "names another)"),
                         ("mldsa", f"Mutual TLS with ML-DSA certificates (key exchange {group})")):
        keys = [k for k in results if k[0] == suite]
        if not keys:
            continue
        rep.heading(title, 3)
        rep.chart(f"handshakes_{suite}.png", f"{title}: median handshake time by direction")
        rows = []
        for k in keys:
            r = results[k]
            row = [k[1]]
            fastest = min(DIRECTIONS, key=lambda d: r["desc"][d]["median"]) if r["complete"] else None
            for d in DIRECTIONS:
                s = r["desc"].get(d)
                txt = f"{s['median']:.2f}" if s else "-"
                row.append(Strong(txt) if d == fastest else txt)
            for l in others:
                v = r["stats"].get(("ratio", (l, l)))
                row.append(f"{v:.2f}x" if v is not None else "-")
            row.append(dir_label(fastest) if r["complete"] else "incomplete")
            rows.append(row)
        if not legend_done:
            label_legend(rep)
            legend_done = True
        if two:
            rep.para("Median handshake time in ms (client -> server). "
                     f"ratio = {LIB_NAME[others[0]]}->{LIB_NAME[others[0]]} time / "
                     "OpenSSL->OpenSSL time.")
        else:
            rep.para("Median handshake time in ms (client -> server). "
                     "LL/oo (Rx->Rx/oo for each of several rustls providers) = library L's own "
                     "pair (L->L) time / OpenSSL->OpenSSL time; fastest "
                     f"only where all {len(DIRECTIONS)} directions were measured.")
        rep.table(["measurement"] + [dir_label(d) for d in DIRECTIONS]
                  + [own_ratio_label(l) for l in others] + ["fastest"], rows,
                  ["l"] + ["r"] * (len(DIRECTIONS) + len(others)) + ["l"])
        if suite == "kem" and not cert_pairs(keys):
            for note in policy_notes([(k[1], None, {d[0] for d in results[k]["desc"]}) for k in keys
                                      if KEM_CERT[k[1]][1] != "ec"], policies):
                rep.para(note)

        rows = []
        for k in keys:
            r = results[k]
            if not r["ratios"]:
                continue
            row = [k[1]]
            for d in DIRECTIONS[1:]:
                rk = ("ratio", d)
                row.append(f"{r['stats'][rk]:.2f} {fmt_ci(r['ci'].get(rk))}".strip()
                           if rk in r["stats"] else "-")
            rows.append(row)
        if rows:
            rep.para("\nTime relative to OpenSSL -> OpenSSL"
                     + (" (bootstrap 95% CI)" if B > 0 else "") + ":")
            rep.table(["measurement"] + [dir_label(d) for d in DIRECTIONS[1:]], rows, collapse=True)

        for p in pairs:
            rows = []
            ds = dstart(*p)
            for k in keys:
                r = results[k]
                if p not in r["blocks"]:
                    continue
                st, ci = r["stats"], r["ci"]
                g = lambda n: f"{st[(n, p)]:+.2f} {fmt_ci(ci.get((n, p)))}".strip()
                ip = g("interop_penalty")
                rows.append([k[1], g("client_effect"),
                             fmt(st[("client_effect", p)] - ds) if ds is not None else "-",
                             g("server_effect"),
                             Strong(ip) if ci.get(("interop_penalty", p), (0, 0))[0] > 0 else ip])
            if not rows:
                continue
            A, Bn = LIB_NAME[p[0]], LIB_NAME[p[1]]
            if two:
                rep.para(f"\n2x2 breakdown in ms (negative = the {Bn} side is faster):")
                rep.bullets([f"client effect = swapping the client from {A} to {Bn}",
                             f"server effect = swapping the server from {A} to {Bn}",
                             "interop penalty = extra time mixed pairs take beyond the sum of the two "
                             "effects (about 0 means mixing implementations costs nothing)"])
            else:
                if not bullets_done:
                    rep.para("\n2x2 breakdowns, one per pair of libraries A vs B whose four cells "
                             "(A->A, A->B, B->A, B->B) were all measured:")
                    rep.bullets(["client effect = swapping the client from A to B",
                                 "server effect = swapping the server from A to B",
                                 "client excl. startup = client effect minus the difference in process "
                                 "startup baseline",
                                 "interop penalty = extra time mixed pairs take beyond the sum of the two "
                                 "effects (about 0 means mixing implementations costs nothing)"])
                    bullets_done = True
                rep.para(f"\n{A} vs {Bn}, 2x2 breakdown in ms (negative = the {Bn} side is faster):")
            rep.table(["measurement", "client effect", "client excl. startup", "server effect",
                       "interop penalty"], rows)

    # Overall
    complete = [r for r in results.values() if r["complete"]]
    if complete or any(r["blocks"] for r in results.values()):
        rep.heading("Overall, all handshake measurements", 3)
    if complete:
        if not two:
            rep.para(f"Over the {len(complete)} measurements where all {len(DIRECTIONS)} directions "
                     "were measured:")
        rows = []
        for d in DIRECTIONS:
            g = 1.0 if d == BASELINE else geomean([r["stats"][("ratio", d)] for r in complete])
            nfast = sum(1 for r in complete
                        if min(DIRECTIONS, key=lambda x: r["desc"][x]["median"]) == d)
            rows.append([dir_label(d), f"{g:.2f}x", f"{nfast}/{len(complete)}"])
        rep.table(["direction", "geo-mean time vs OpenSSL->OpenSSL", "fastest in"], rows,
                  ["l", "r", "r"], finding=True)
    for p in pairs:
        blk = [(k, r) for k, r in results.items() if p in r["blocks"]]
        if not blk:
            continue
        mean = lambda n: statistics.mean(r["stats"][(n, p)] for _, r in blk)
        ce, se, ip = mean("client_effect"), mean("server_effect"), mean("interop_penalty")
        ds = dstart(*p)
        lead = "\nMean" if two else (f"\n{LIB_NAME[p[0]]} vs {LIB_NAME[p[1]]} "
                                      f"({len(blk)} measurements): mean")
        rep.para(f"{lead} client effect {ce:+.2f} ms"
                 + (f" ({ce - ds:+.2f} ms excluding process startup)" if ds is not None else "")
                 + f", server effect {se:+.2f} ms, interop penalty {ip:+.2f} ms.", finding=True)
        key = ("interop_penalty", p)
        sig = [k for k, r in blk if key in r["ci"] and (r["ci"][key][0] > 0 or r["ci"][key][1] < 0)]
        if B > 0:
            cost = [k for k in sig if results[k]["ci"][key][0] > 0]
            cheap = [k for k in sig if results[k]["ci"][key][1] < 0]
            fmt_list = lambda ks: ", ".join(
                f"{k[1]} ({results[k]['stats'][key]:+.2f} ms)" for k in ks)
            who = "" if two else f"{LIB_NAME[p[0]]} vs {LIB_NAME[p[1]]}: "
            rep.para(who + "Mixed pairs measurably SLOWER than the additive model (a real interop cost): "
                     + (fmt_list(cost) if cost else "none"), finding=True)
            if cheap:
                rep.para(who + "Mixed pairs measurably FASTER than the additive model (not a cost; the "
                         "client and server effects just don't add up exactly): " + fmt_list(cheap))
    return results


def _norm_group(name):
    """Group name as the libraries spell it (MLKEM768, ML_KEM_768, secp256r1, P-256) -> one form."""
    n = re.sub(r"[^a-z0-9]", "", name.lower())
    for long, short in (("prime256v1", "p256"), ("secp256r1", "p256"), ("secp384r1", "p384"),
                        ("secp521r1", "p521")):
        if n.startswith(long):
            n = short + n[len(long):]
    return n


# --------------------------------------------------------------------------
# In-process handshakes (pqcbench.sh --inproc, hsloop clients)
# --------------------------------------------------------------------------
def load_inproc(runs):
    """-> (data, init): data[(suite, measurement)][(client, server)] = {"total": [ms],
    "handshake": [ms], "connect": [ms], "response": [ms]} for successful handshakes;
    init[client] = [init_ms per pair run]."""
    data = OrderedDict()
    init = defaultdict(list)
    envs = load_env(runs)
    for run, env in envs:
        main_group = mldsa_group([run])
        certs, issuer = run_certs(env)
        for fname, suite in (("handshakes_inproc_raw.csv", "kem"), ("mldsa_handshakes_inproc_raw.csv", "mldsa")):
            p = os.path.join(run, fname)
            if not os.path.isfile(p):
                continue
            for r in read_rows(run, p):
                if r.get("ok") != "1":
                    continue
                if suite == "kem":
                    name = kem_name(r["group"], r.get("cert") or certs[0], issuer)
                else:
                    name = f"ML-DSA {r['profile']} ({LIB_NAME.get(r['producer'], r['producer'])} chain)"
                    g = r.get("negotiated_group", "")
                    # same naming as load_handshakes (fallback groups are separate measurements)
                    if g and main_group != "?" and _norm_group(g) != _norm_group(main_group):
                        name += f" via {g}"
                cell = data.setdefault((suite, name), {}).setdefault(
                    (r["client"], r["server"]), {"total": [], "handshake": [], "connect": [], "response": []})
                cell["total"].append(float(r["total_ms"]))
                cell["handshake"].append(float(r["handshake_ms"]))
                for phase in ("connect", "response"):
                    if r.get(f"{phase}_ms"):
                        cell[phase].append(float(r[f"{phase}_ms"]))
        for fname in ("handshakes_inproc_summary.csv", "mldsa_handshakes_inproc_summary.csv"):
            p = os.path.join(run, fname)
            if os.path.isfile(p):
                for r in read_rows(run, p):
                    if r.get("init_ms"):
                        init[r["client"]].append(float(r["init_ms"]))
    return order_kem(data, envs), init


def analyse_inproc(inproc, init, hs, startup, rep, outdir, entropy):
    """In-process timing next to the per-process timing of the same pairs."""
    if not inproc:
        return
    rep.heading("In-process handshakes (hsloop clients, one process per pair)", 3)
    rep.para("With --inproc, each pair was also timed by an hsloop client: all its handshakes in "
             "one client process, each a full handshake on a new TCP connection with a new "
             "connection object from one shared client setup. Process start, library start-up "
             "and client setup happen once (init), not in every sample. Same servers, groups "
             "and certificates as the per-process timing.", note=True)

    # library start-up, measured directly
    rows = []
    for l in LIBS:
        if l in init:
            rows.append([LIB_NAME[l], f"{statistics.median(init[l]):.2f}",
                         f"{startup[l]:.2f}" if l in startup else "-"])
    if rows:
        note = ("; s2n-tls's includes seeding AWS-LC's CPU-jitter entropy source"
                if entropy.get("s2n") == "jitter" else
                "; AWS-LC built without CPU-jitter entropy" if entropy.get("s2n") == "nojitter" else "")
        for l in RUSTLS_PROVIDER:
            if l in init and entropy.get(l) == "jitter":
                note += f"; {LIB_NAME[l]}'s includes seeding its AWS-LC's CPU-jitter entropy source"
        rep.para("Client start-up: init = library start-up and client setup inside an hsloop client "
                 "(median over its runs), next to the per-process startup baseline (a whole process "
                 f"until it exits or fails to connect){note}:")
        rep.table(["client", "hsloop init ms", "per-process startup baseline ms"], rows, finding=True)

    comp = []
    for suite, title in (("kem", "Key exchange"), ("mldsa", "Mutual TLS with ML-DSA certificates")):
        keys = [k for k in inproc if k[0] == suite]
        if not keys:
            continue
        dirs = [d for d in DIRECTIONS if any(d in inproc[k] for k in keys)]
        for what, label in (("total", "whole sample (connect, handshake, request/response, close)"),
                            ("handshake", "TLS handshake only (after TCP connect)")):
            rows = []
            for k in keys:
                cells = inproc[k]
                meds = {d: statistics.median(cells[d][what]) for d in dirs if d in cells and cells[d][what]}
                fastest = min(meds, key=meds.get) if len(meds) == len(dirs) and len(dirs) > 1 else None
                row = [k[1]]
                for d in dirs:
                    txt = f"{meds[d]:.3f}" if d in meds else "-"
                    row.append(Strong(txt) if d == fastest else txt)
                rows.append(row)
            rep.para(f"\n{title}, in-process median ms, {label}:")
            rep.table(["measurement"] + [dir_label(d) for d in dirs], rows,
                      ["l"] + ["r"] * len(dirs), collapse=(what == "handshake"))
        for k in keys:
            for d, cell in inproc[k].items():
                pp = hs.get(k, {}).get(d)
                if not pp or not cell["total"]:
                    continue
                comp.append((suite, k[1], d, statistics.median(pp), statistics.median(cell["total"]),
                             statistics.median(cell["handshake"])))

    if comp:
        with open(os.path.join(outdir, "inproc_comparison.csv"), "w", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(["suite", "measurement", "client", "server", "per_process_median_ms",
                         "inproc_median_ms", "inproc_handshake_median_ms", "difference_ms"])
            for s, m, d, pp, ip, hsk in comp:
                wr.writerow([s, m, d[0], d[1], f"{pp:.3f}", f"{ip:.3f}", f"{hsk:.3f}", f"{pp - ip:.3f}"])
        rows = []
        for l in LIBS:
            mine = [c for c in comp if c[2][0] == l]
            if not mine:
                continue
            pp = statistics.mean(c[3] for c in mine)
            ip = statistics.mean(c[4] for c in mine)
            rows.append([LIB_NAME[l], len(mine), f"{pp:.2f}", f"{ip:.3f}", f"{pp - ip:.2f}",
                         f"{100 * (pp - ip) / pp:.0f}%"])
        rep.para("\nPer-process and in-process medians of the same pairs, mean over the pairs each "
                 "client was timed in (difference = what one process per handshake adds):")
        rep.table(["client", "pairs", "per-process ms", "in-process ms", "difference ms",
                   "share of per-process time"], rows, finding=True)


def analyse_cert_costs(hs, inproc, rep, outdir, policies):
    """What each server certificate adds over ECDSA P-256 for the same key-exchange group and
    issuer, over the client -> server pairs measured with both (in-process: the TLS handshake
    phase; per-process: the whole process). -> True if it wrote cert_costs.csv."""
    pairs = cert_pairs(list(dict.fromkeys(list(hs) + list(inproc))))
    if not pairs:
        return False
    timings = [(t, data) for t, data in (
        ("in-process handshake", {k[1]: {d: c["handshake"] for d, c in cells.items() if c["handshake"]}
                                  for k, cells in inproc.items() if k[0] == "kem"}),
        ("per-process", {k[1]: {d: v for d, v in cells.items() if v}
                         for k, cells in hs.items() if k[0] == "kem"})) if data]
    # costs[timing][measurement] = [(direction, median with the certificate, with ECDSA P-256)]
    costs = {t: {} for t, _ in timings}
    for t, data in timings:
        for m, ec in pairs:
            dirs = [d for d in DIRECTIONS if d in data.get(m, {}) and d in data.get(ec, {})]
            if dirs:
                costs[t][m] = [(d, statistics.median(data[m][d]), statistics.median(data[ec][d])) for d in dirs]
    if not any(costs.values()):
        return False

    with open(os.path.join(outdir, "cert_costs.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["timing", "group", "cert", "issuer", "measurement", "ecdsa_measurement", "client",
                     "server", "median_ms", "ecdsa_median_ms", "difference_ms"])
        for t, _ in timings:
            for m, ec in pairs:
                g, c, iss = KEM_CERT[m]
                for d, mm, em in costs[t].get(m, []):
                    wr.writerow([t, g, c, iss, m, ec, d[0], d[1], f"{mm:.3f}", f"{em:.3f}", f"{mm - em:.3f}"])

    rep.heading("Server certificate cost (vs ECDSA P-256)", 3)
    rep.para("What each server certificate adds to the handshake over the ECDSA P-256 certificate for "
             "the same key-exchange group (and issuer), compared only over the client -> server pairs "
             "measured with both (pairs that can't use a certificate are skipped): extra ms = the "
             "median over those pairs of (median with the certificate - median with ECDSA P-256). "
             "In-process: the TLS handshake phase of the hsloop clients (after the TCP connect, "
             "without process start-up); ratio = median over the pairs of the in-process handshake "
             "time with the certificate / with ECDSA P-256. Per-process: the whole handshake process.",
             note=True)
    nd = {"in-process handshake": 3, "per-process": 2}
    short = {"in-process handshake": "in-process", "per-process": "per-process"}
    head = ["group", "certificate"]
    for t, _ in timings:
        head += ([f"{short[t]} pairs", f"{short[t]} extra ms", f"{short[t]} range"]
                 + (["in-process ratio"] if t == "in-process handshake" else []))
    rows = []
    for m, _ in pairs:
        if not any(costs[t].get(m) for t in costs):
            continue
        g, c, iss = KEM_CERT[m]
        row = [g, cert_desc(c, iss)]
        for t, _ in timings:
            v = costs[t].get(m)
            if not v:
                row += ["-"] * (4 if t == "in-process handshake" else 3)
                continue
            diff = [mm - em for _, mm, em in v]
            row += [len(v), f"{statistics.median(diff):+.{nd[t]}f}",
                    f"[{min(diff):+.{nd[t]}f}, {max(diff):+.{nd[t]}f}]"]
            if t == "in-process handshake":
                row.append(f"{statistics.median(mm / em for _, mm, em in v):.2f}x")
        rows.append(row)
    rep.para("Extra time over ECDSA P-256, median over the pairs measured with both certificates "
             "(range = smallest and largest pair):")
    rep.table(head, rows, ["l", "l"] + ["r"] * (len(head) - 2), finding=True)

    # by server library (the server signs with the certificate): every group and client pooled
    t = timings[0][0]
    by = defaultdict(lambda: defaultdict(list))
    for m, _ in pairs:
        for d, mm, em in costs[t].get(m, []):
            by[cert_desc(*KEM_CERT[m][1:])][d[1]].append(mm - em)
    srvs = [l for l in LIBS if any(l in v for v in by.values())]
    if by and len(srvs) > 1:
        rep.para(f"\nBy server library ({t}): extra ms over ECDSA P-256, median over every group and "
                 "client measured with both certificates (pairs in brackets):")
        rep.table(["certificate"] + [LIB_NAME[l] for l in srvs],
                  [[cd] + [f"{statistics.median(v[l]):+.{nd[t]}f} ({len(v[l])})" if v.get(l) else "-"
                           for l in srvs] for cd, v in by.items()], ["l"] + ["r"] * len(srvs))
    for note in policy_notes([(m, ec, {d[0] for t in costs for d, _, _ in costs[t].get(m, [])})
                              for m, ec in pairs], policies):
        rep.para(note)
    return True


def analyse_round_trips(inproc, hs, startup, ns, rep, outdir):
    """Network-simulation runs (pqcbench.sh --rtt) and remote-server runs (--remote): each sample
    in round trips of the path, so extra round trips stand out (HelloRetryRequest, a flight over
    TCP's initial window, programs waiting for acknowledgements). In-process phases where
    measured; per-process medians minus the client's start-up. ns: netsim_settings' or
    remote_settings' settings. -> True if it wrote round_trips.csv."""
    rtt = ns.get("measured") or ns.get("rtt")
    if not rtt or not (inproc or hs):
        return False
    rep.heading(f"Round trips on {ns.get('path', 'the simulated path')}", 3)
    rep.para(f"{ns.get('what', 'Network simulation')}: {ns['line']}. Times in round trips of {rtt:.1f} ms (the RTT "
             "measured at the start and end of the runs, averaged). A sample has the TCP connect "
             "(1 round trip), the TLS 1.3 handshake (1) and the HTTP request and response (1 or "
             "more, depending on how client and server write and close); compare the counts "
             "between libraries and measurements. Extra round trips come from a "
             "HelloRetryRequest, a flight larger than TCP's initial window (10 segments), or a "
             "program that sends in small writes and waits for acknowledgements.", note=True)
    rt = lambda ms: ms / rtt
    med = lambda c, p: statistics.median(c[p]) if c.get(p) else None
    fmt_rt = lambda ms: "-" if ms is None else f"{rt(ms):.1f}"
    rows_csv = []
    for k, cells in inproc.items():
        for d, c in cells.items():
            m = {p: med(c, p) for p in ("total", "connect", "handshake", "response")}
            rows_csv.append([k[0], k[1], d[0], d[1], "in-process", f"{rtt:g}", f"{m['total']:.3f}"] +
                            ["" if m[p] is None else f"{rt(m[p]):.2f}"
                             for p in ("total", "connect", "handshake", "response")])
    for k, cells in hs.items():
        for d, samples in cells.items():
            if samples and d[0] in startup:
                adj = statistics.median(samples) - startup[d[0]]
                rows_csv.append([k[0], k[1], d[0], d[1], "per-process", f"{rtt:g}", f"{adj:.3f}",
                                 f"{rt(adj):.2f}", "", "", ""])
    libs = [l for l in LIBS if any((l, l) in cells for cells in inproc.values())]
    if libs:
        def phases(c):
            return (f"{fmt_rt(med(c, 'total'))} ({fmt_rt(med(c, 'connect'))} / "
                    f"{fmt_rt(med(c, 'handshake'))} / {fmt_rt(med(c, 'response'))})")
        rep.para("In process, each library with itself: the whole sample in round trips, and in "
                 "brackets the TCP connect / TLS handshake / request and response:")
        rep.table(["measurement"] + [LIB_NAME[l] for l in libs],
                  [[k[1]] + [phases(cells[(l, l)]) if (l, l) in cells else "-" for l in libs]
                   for k, cells in inproc.items()], ["l"] + ["r"] * len(libs))
    libs = [l for l in LIBS if l in startup and any(cells.get((l, l)) for cells in hs.values())]
    if libs:
        rep.para("\nPer process, each library with itself: median minus the client's start-up, in "
                 "round trips:")
        rep.table(["measurement"] + [LIB_NAME[l] for l in libs],
                  [[k[1]] + [fmt_rt(statistics.median(cells[(l, l)]) - startup[l]) if cells.get((l, l)) else "-"
                             for l in libs] for k, cells in hs.items()], ["l"] + ["r"] * len(libs))
    with open(os.path.join(outdir, "round_trips.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["suite", "measurement", "client", "server", "timing", "rtt_ms", "median_ms",
                     "round_trips", "connect_rtts", "handshake_rtts", "response_rtts"])
        wr.writerows(rows_csv)
    return True


# --------------------------------------------------------------------------
# Versions mode: negotiation, downgrade, HelloRetryRequest
# --------------------------------------------------------------------------
VS_ORDER = ["base13", "neg13", "neg13-both", "base12", "down12-server", "down12-client",
            "refuse-13v12", "refuse-12v13", "hybrid13", "hybrid-down12", "hybrid-hrr",
            "pq13", "pq-down12", "pq-vs-classical", "mldsa13", "mldsa-down12"]
# (scenario A, scenario B, label): cost of A relative to B
VS_COMPARISONS = [
    ("neg13", "base13", "client negotiates 1.2-1.3 vs pinned 1.3"),
    ("neg13-both", "base13", "both negotiate vs both pinned 1.3"),
    ("base12", "base13", "TLS 1.2 vs TLS 1.3 (both pinned)"),
    ("down12-server", "base13", "downgraded to 1.2 (server cap) vs native 1.3"),
    ("down12-server", "base12", "downgraded to 1.2 (server cap) vs native 1.2"),
    ("down12-client", "base12", "downgraded to 1.2 (client cap) vs native 1.2"),
    ("hybrid13", "base13", "hybrid ML-KEM vs X25519 on TLS 1.3"),
    ("hybrid-down12", "hybrid13", "hybrid client downgraded to 1.2 vs staying on 1.3"),
    ("hybrid-hrr", "base13", "HelloRetryRequest to X25519 vs direct X25519"),
    ("hybrid-hrr", "hybrid13", "HelloRetryRequest to X25519 vs hybrid without HRR"),
    ("mldsa13", "hybrid13", "ML-DSA-65 cert vs ECDSA P-256 cert"),
    ("refuse-13v12", "base13", "time to refusal vs a full 1.3 handshake"),
]


def load_versions(runs):
    """-> (outcomes {(scen, c, s): row}, samples {(scen, c, s): [ms]})"""
    outcomes, samples = {}, defaultdict(list)
    for run in runs:
        p = os.path.join(run, "versions_results.csv")
        if os.path.isfile(p):
            for r in read_rows(run, p):
                outcomes.setdefault((r["scenario"], r["client"], r["server"]), r)
        p = os.path.join(run, "versions_handshakes_raw.csv")
        if os.path.isfile(p):
            for r in read_rows(run, p):
                samples[(r["scenario"], r["client"], r["server"])].append(float(r["ms"]))
    return outcomes, samples


def diff_ci(a, b, B, seed=7):
    """95% bootstrap CI for median(a) - median(b)."""
    if B <= 0 or len(a) < 2 or len(b) < 2:
        return None
    rng = random.Random(seed)
    d = sorted(statistics.median(rng.choices(a, k=len(a))) - statistics.median(rng.choices(b, k=len(b)))
               for _ in range(B))
    return quantile(d, 0.025), quantile(d, 0.975)


def _rtts(row):
    try:
        return int(row.get("handshake_rtts") or "")
    except ValueError:
        return None


def analyse_versions(outcomes, samples, B, rtt_ms, rep, outdir):
    if not outcomes:
        return None
    scens = [s for s in VS_ORDER if any(k[0] == s for k in outcomes)]
    scens += sorted({k[0] for k in outcomes} - set(scens))
    rep.heading("3. TLS version negotiation and downgrade")

    # outcomes
    rows = []
    for sc in scens:
        row = [sc]
        for d in DIRECTIONS:
            o = outcomes.get((sc,) + d)
            if not o:
                row.append("-")
                continue
            txt = f"{o['version']} {o['group']}" if o["outcome"] == "ok" else "refused"
            flags = []
            if o.get("hrr") == "yes":
                flags.append("HRR")
            if o.get("pq_lost") == "yes":
                flags.append("PQ lost")
            if o.get("result") == "FAIL":
                flags.append("UNEXPECTED")
            txt += f" ({', '.join(flags)})" if flags else ""
            row.append(Strong(txt) if o.get("result") == "FAIL" else txt)
        rows.append(row)
    rep.para("Outcome of each scenario (client -> server). HRR = HelloRetryRequest; "
             "PQ lost = the client offered post-quantum key exchange but got classical.")
    label_legend(rep)
    rep.table(["scenario"] + [dir_label(d) for d in DIRECTIONS], rows, ["l"] * (len(DIRECTIONS) + 1))
    nfail = sum(1 for o in outcomes.values() if o.get("result") == "FAIL")
    npql = sum(1 for o in outcomes.values() if o.get("pq_lost") == "yes")
    rep.para(f"\n{len(outcomes) - nfail} of {len(outcomes)} cases behaved as expected; "
             f"{npql} connected without post-quantum protection although the client offered it.",
             finding=True)

    # timings
    med = {}
    for k, v in samples.items():
        if v:
            med[k] = statistics.median(v)
    if med:
        rows = []
        for sc in scens:
            row = [sc]
            for d in DIRECTIONS:
                k = (sc,) + d
                if k not in med:
                    row.append("-")
                    continue
                o = outcomes.get(k, {})
                r = _rtts(o)
                row.append(("R " if o.get("outcome") == "refused" else "") + f"{med[k]:.2f}"
                           + (f" [{r}]" if r else ""))
            rows.append(row)
        rep.para("\nMedian time in ms [handshake round trips]; R = time until the handshake was refused.")
        rep.table(["scenario"] + [dir_label(d) for d in DIRECTIONS], rows, collapse=True)

    # comparisons
    comp_rows, csv_rows, chart = [], [], []
    for a, b, label in VS_COMPARISONS:
        row = [label]
        for d in DIRECTIONS:
            ka, kb = (a,) + d, (b,) + d
            if ka not in med or kb not in med:
                row.append("-")
                continue
            delta = med[ka] - med[kb]
            ci = diff_ci(samples[ka], samples[kb], B)
            sig = ci is not None and (ci[0] > 0 or ci[1] < 0)
            ra, rb = _rtts(outcomes.get(ka, {})), _rtts(outcomes.get(kb, {}))
            extra = (ra - rb) if (ra is not None and rb is not None) else None
            txt = f"{delta:+.2f}" + (f" {fmt_ci(ci)}" if ci else "") + ("*" if sig else "")
            row.append(Strong(txt) if sig else txt)
            csv_rows.append([a, b, label, d[0], d[1], f"{med[ka]:.3f}", f"{med[kb]:.3f}", f"{delta:.3f}",
                             f"{ci[0]:.3f}" if ci else "", f"{ci[1]:.3f}" if ci else "",
                             "" if extra is None else extra,
                             f"{delta + extra * rtt_ms:.3f}" if (rtt_ms and extra is not None) else ""])
            chart.append((label, d, delta, ci))
        comp_rows.append(row)
    rep.chart("versions_costs.png", "What TLS negotiation, downgrade and HRR cost")
    rep.para("\nWhat each factor costs: difference of medians in ms (positive = slower), per direction"
             + (", with bootstrap 95% CI; * = CI excludes 0" if B > 0 else "") + ".")
    rep.table(["comparison"] + [dir_label(d) for d in DIRECTIONS], comp_rows)

    extra_rows = []
    for a, b, label in VS_COMPARISONS:
        ex = set()
        for d in DIRECTIONS:
            ra, rb = _rtts(outcomes.get((a,) + d, {})), _rtts(outcomes.get((b,) + d, {}))
            if ra is not None and rb is not None:
                ex.add(ra - rb)
        if ex and ex != {0}:
            extra_rows.append([label, "/".join(f"{x:+d}" for x in sorted(ex))])
    if extra_rows:
        rep.para("\nComparisons that also change the number of handshake round trips "
                 "(invisible on localhost, one full network RTT each on a real link):")
        rep.table(["comparison", "extra round trips"], extra_rows, ["l", "r"])

    if rtt_ms:
        rows = []
        for a, b, label in VS_COMPARISONS:
            row = [label]
            for d in DIRECTIONS:
                ka, kb = (a,) + d, (b,) + d
                ra, rb = _rtts(outcomes.get(ka, {})), _rtts(outcomes.get(kb, {}))
                if ka in med and kb in med and ra is not None and rb is not None:
                    row.append(f"{med[ka] - med[kb] + (ra - rb) * rtt_ms:+.1f}")
                else:
                    row.append("-")
            rows.append(row)
        rep.para(f"\nProjected onto a {rtt_ms:g} ms round-trip link (localhost difference + "
                 f"extra handshake round trips x {rtt_ms:g} ms):")
        rep.table(["comparison"] + [dir_label(d) for d in DIRECTIONS], rows)
    else:
        rep.para("\nTip: --rtt 50 projects these differences onto a 50 ms round-trip network.", note=True)

    with open(os.path.join(outdir, "versions_comparisons.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["scenario_a", "scenario_b", "comparison", "client", "server", "median_a_ms",
                     "median_b_ms", "delta_ms", "ci_low", "ci_high", "extra_handshake_rtts",
                     f"projected_delta_ms_at_rtt_{rtt_ms:g}" if rtt_ms else "projected_delta_ms"])
        wr.writerows(csv_rows)
    return chart


def plot_versions(chart, outdir, plt):
    if not chart:
        return None
    labels = []
    for lbl, _, _, _ in chart:
        if lbl not in labels:
            labels.append(lbl)
    n = len(labels)
    ncol, lrows = _legend_rows()
    top = 0.95 + 0.2 * (lrows - 1) + _key_height()
    per = _group_height()
    fig, ax = plt.subplots(figsize=(9.5, max(3.5, per * n + 0.85 + top)), facecolor=SURFACE)
    _style(ax)
    bar_h, gap, off = _bar_layout()
    idx = {l: i for i, l in enumerate(labels)}
    seen = set()
    for lbl, d, delta, ci in chart:
        di = DIRECTIONS.index(d)
        yy = (n - 1 - idx[lbl]) + off - di * (bar_h + gap)
        ax.barh(yy, delta, height=bar_h, color=dir_color(d),
                label=_legend_label(d) if d not in seen else None)
        seen.add(d)
        if ci:
            ax.plot([ci[0], ci[1]], [yy, yy], color=INK2, linewidth=1)
    ax.axvline(0, color=AXIS, linewidth=1)
    ax.set_yticks([n - 1 - i for i in range(n)])
    if len(DIRECTIONS) > 16:          # (default 5% margins are inches on a tall chart)
        ax.set_ylim(-0.5, n - 0.5)
    ax.set_yticklabels(labels, color=INK, fontsize=8.5)
    ax.set_xlabel("difference of median handshake time, ms (line = 95% CI)   <- faster | slower ->",
                  color=INK2, fontsize=9)
    _fig_header(fig, "What TLS negotiation, downgrade and HRR cost (localhost)")
    _fig_legend(fig, ax, 0.94, ncol)
    fig.tight_layout(rect=(0, 0, 1, 1 - top / fig.get_size_inches()[1]))
    path = os.path.join(outdir, "versions_costs.png")
    fig.savefig(path, dpi=160, facecolor=SURFACE)
    plt.close(fig)
    return path


# --------------------------------------------------------------------------
# Packet captures (pqcbench.sh --capture): wire sizes and handshake structure
#   Pure-Python pcap/pcapng reader: no Wireshark needed. Only the plaintext
#   parts of the handshake are parsed (ClientHello, ServerHello/HRR, alerts,
#   the whole TLS 1.2 handshake); byte counts cover the whole connection.
# --------------------------------------------------------------------------
import struct

TLS_GROUPS = {
    0x0017: "P-256", 0x0018: "P-384", 0x0019: "P-521", 0x001d: "X25519", 0x001e: "X448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x11eb: "SecP256r1MLKEM768", 0x11ec: "X25519MLKEM768", 0x11ed: "SecP384r1MLKEM1024",
}
TLS_VERSIONS = {0x0303: "1.2", 0x0304: "1.3", 0x0302: "1.1", 0x0301: "1.0"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          42: "bad_certificate", 43: "unsupported_certificate", 46: "certificate_unknown",
          47: "illegal_parameter", 48: "unknown_ca", 50: "decode_error", 51: "decrypt_error",
          70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
          109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
          116: "certificate_required", 120: "no_application_protocol"}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
HS_NAMES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
            11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest",
            14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished"}


def read_packets(path):
    """Yield (linktype, frame bytes) from a pcap or pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        linktype = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFFF
        off = 24
        while off + 16 <= len(data):
            incl = struct.unpack(e + "I", data[off + 8:off + 12])[0]
            yield linktype, data[off + 16:off + 16 + incl]
            off += 16 + incl
        return
    if magic != b"\x0a\x0d\x0d\x0a":
        return
    e, off, links = "<", 0, []
    while off + 12 <= len(data):
        btype = struct.unpack(e + "I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:                       # section header: byte order
            e = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            btype = 0x0A0D0D0A
            links = []
        blen = struct.unpack(e + "I", data[off + 4:off + 8])[0]
        if blen < 12:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1:                                 # interface description
            links.append(struct.unpack(e + "H", body[:2])[0])
        elif btype == 6:                               # enhanced packet
            iface, _, _, cap = struct.unpack(e + "IIII", body[:16])
            if iface < len(links):
                yield links[iface], body[20:20 + cap]
        elif btype == 3 and links:                     # simple packet
            yield links[0], body[4:]
        off += blen


def ip_payload(linktype, fr):
    """-> (ip version, ip packet) or None"""
    if linktype == 1:                                  # Ethernet
        et, o = struct.unpack(">H", fr[12:14])[0], 14
        while et in (0x8100, 0x88a8) and len(fr) >= o + 4:
            et, o = struct.unpack(">H", fr[o + 2:o + 4])[0], o + 4
        pkt = fr[o:]
    elif linktype in (0, 108):                         # BSD loopback (macOS lo0)
        pkt = fr[4:]
    elif linktype == 113:                              # Linux cooked
        pkt = fr[16:]
    elif linktype == 276:                              # Linux cooked v2
        pkt = fr[20:]
    elif linktype in (12, 101, 228, 229):             # raw IP
        pkt = fr
    else:
        return None
    if not pkt:
        return None
    v = pkt[0] >> 4
    return (v, pkt) if v in (4, 6) else None


def tcp_segments(path):
    """Yield (src_port, dst_port, seq, flags, payload) for TCP packets."""
    for lt, fr in read_packets(path):
        r = ip_payload(lt, fr)
        if not r:
            continue
        v, pkt = r
        if v == 4:
            ihl = (pkt[0] & 0x0F) * 4
            if pkt[9] != 6:
                continue
            total = struct.unpack(">H", pkt[2:4])[0]
            seg = pkt[ihl:total] if total else pkt[ihl:]
        else:
            if pkt[6] != 6:                            # no IPv6 extension-header walking
                continue
            plen = struct.unpack(">H", pkt[4:6])[0]
            seg = pkt[40:40 + plen]
        if len(seg) < 20:
            continue
        sp, dp, seq = struct.unpack(">HHI", seg[:8])
        doff = (seg[12] >> 4) * 4
        yield sp, dp, seq, seg[13], seg[doff:]


def reassemble(segs):
    """segs: [(seq, payload)] -> in-order byte stream (retransmissions dropped)."""
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    out = bytearray()
    for s, p in sorted(segs, key=lambda x: x[0]):
        start = (s - base) & 0xFFFFFFFF
        if start + len(p) <= len(out):
            continue
        if start > len(out):                           # gap: keep what we have
            break
        out += p[len(out) - start:]
    return bytes(out)


def tls_records(stream):
    off = 0
    while off + 5 <= len(stream):
        ctype, ver, ln = stream[off], struct.unpack(">H", stream[off + 1:off + 3])[0], \
            struct.unpack(">H", stream[off + 3:off + 5])[0]
        body = stream[off + 5:off + 5 + ln]
        if len(body) < ln:
            break
        yield ctype, ver, body
        off += 5 + ln


def plaintext_handshake(stream):
    """-> (list of (type, body) handshake messages sent in the clear, alerts, encrypted_seen)"""
    buf, msgs, alerts, enc = b"", [], [], False
    for ctype, _, body in tls_records(stream):
        if ctype == 22 and not enc:
            buf += body
            while len(buf) >= 4:
                t, ln = buf[0], int.from_bytes(buf[1:4], "big")
                if len(buf) < 4 + ln:
                    break
                msgs.append((t, buf[4:4 + ln]))
                buf = buf[4 + ln:]
        elif ctype == 21 and len(body) == 2:
            alerts.append((body[0], body[1]))
        elif ctype == 23:
            enc = True
        elif ctype == 20:
            pass                                       # ChangeCipherSpec
    return msgs, alerts, enc


def parse_exts(body, off):
    exts = {}
    if off + 2 > len(body):
        return exts
    end = off + 2 + struct.unpack(">H", body[off:off + 2])[0]
    off += 2
    while off + 4 <= end:
        t, ln = struct.unpack(">HH", body[off:off + 4])
        exts[t] = body[off + 4:off + 4 + ln]
        off += 4 + ln
    return exts


def parse_client_hello(b):
    off = 2 + 32
    off += 1 + b[off]
    off += 2 + struct.unpack(">H", b[off:off + 2])[0]
    off += 1 + b[off]
    exts = parse_exts(b, off)
    shares = []
    ks = exts.get(51)
    if ks and len(ks) >= 2:
        o = 2
        while o + 4 <= len(ks):
            g, ln = struct.unpack(">HH", ks[o:o + 4])
            shares.append((TLS_GROUPS.get(g, hex(g)), ln))
            o += 4 + ln
    return {"key_shares": shares}


def parse_server_hello(b):
    ver = TLS_VERSIONS.get(struct.unpack(">H", b[:2])[0], "?")
    rnd = b[2:34]
    off = 34
    off += 1 + b[off]
    off += 2 + 1                                       # cipher suite + compression
    exts = parse_exts(b, off)
    if 43 in exts and len(exts[43]) >= 2:
        ver = TLS_VERSIONS.get(struct.unpack(">H", exts[43][:2])[0], ver)
    group = None
    if 51 in exts and len(exts[51]) >= 2:
        group = TLS_GROUPS.get(struct.unpack(">H", exts[51][:2])[0], None)
    return {"hrr": rnd == HRR_RANDOM, "version": ver, "group": group}


def flight_sizes(order, c2s):
    """Handshake flight sizes and their TCP segment counts from packet order.
    order: [(dir 'c'|'s', stream offset, length)] in capture order.
    server flight = everything the server sent before the client's second flight
    (so it includes a HelloRetryRequest); client flight = ClientHello(s) plus the
    client's second flight (which also carries the small HTTP request). A client
    packet holding only a ChangeCipherSpec (TLS 1.3 middlebox compatibility) isn't
    the second flight: clients send it as soon as the ServerHello arrives, which
    can be before the rest of a server flight written message by message.
    -> dict: server/client _bytes and _segments, and the client flight split into
    hello_ (what it sent before its second flight) and second_ bytes and segments."""
    last_ch_end, off = None, 0
    for ctype, _, body in tls_records(c2s):
        if ctype == 22 and body[:1] == b"\x01":
            last_ch_end = off + 5 + len(body)
        off += 5 + len(body)
    size = lambda part, side: sum(n for d, _, n in part if d == side)
    count = lambda part, side: sum(1 for d, _, _ in part if d == side)
    # segments on a 1,500-byte-MTU path: each packet as the 1,448-byte segments it would be
    mss_count = lambda part, side: sum(-(-n // MTU1500_MSS) for d, _, n in part if d == side)

    def result(server_part, client_part, i2):
        hello = client_part[:i2] if i2 is not None else client_part
        second = client_part[i2:] if i2 is not None else []
        out = {}
        for name, part, side in (("server", server_part, "s"), ("client", client_part, "c"),
                                 ("hello", hello, "c"), ("second", second, "c")):
            out.update({f"{name}_bytes": size(part, side), f"{name}_segments": count(part, side),
                        f"{name}_mss_segments": mss_count(part, side)})
        return out
    if last_ch_end is None:
        return result(order, order, None)

    def ccs_only(o, n):
        # the packet's records must fill it: one that starts with a ChangeCipherSpec and
        # goes on into the Certificate is the second flight
        recs = list(tls_records(c2s[o:o + n]))
        return (bool(recs) and all(t == 20 for t, _, _ in recs)
                and sum(5 + len(b) for _, _, b in recs) == n)

    i2 = next((i for i, (d, o, n) in enumerate(order)
               if d == "c" and o >= last_ch_end and not ccs_only(o, n)), None)
    if i2 is None:                                     # refused before the client's second flight
        return result(order, order, None)
    j = next((k for k in range(i2 + 1, len(order)) if order[k][0] == "s"), None)
    return result(order[:i2], order[:j] if j is not None else order, i2)


def analyse_capture(path, window="segments"):
    """window: how the capturing OS counts TCP's initial window (see round_trips)."""
    segs = defaultdict(list)
    server_port, packets, raw = None, 0, []
    for sp, dp, seq, flags, payload in tcp_segments(path):
        packets += 1
        if flags & 0x02 and not flags & 0x10 and server_port is None:   # SYN without ACK
            server_port = dp
        if payload:
            segs[(sp, dp)].append((seq, payload))
            raw.append((sp, dp, seq, len(payload)))
    if server_port is None:
        return None
    c2s = reassemble([x for (sp, dp), v in segs.items() if dp == server_port for x in v])
    s2c = reassemble([x for (sp, dp), v in segs.items() if sp == server_port for x in v])
    base = {}
    for (sp, dp), v in segs.items():
        base["s" if sp == server_port else "c"] = min(q for q, _ in v)
    order, seen = [], set()
    for sp, dp, seq, n in raw:
        d = "s" if sp == server_port else "c"
        rel = (seq - base[d]) & 0xFFFFFFFF
        if (d, rel) in seen:                           # retransmission
            continue
        seen.add((d, rel))
        order.append((d, rel, n))
    fl = flight_sizes(order, c2s)
    cm, calerts, _ = plaintext_handshake(c2s)
    sm, salerts, _ = plaintext_handshake(s2c)
    res = {"packets": packets, "bytes_c2s": len(c2s), "bytes_s2c": len(s2c),
           "server_flight_bytes": fl["server_bytes"], "client_flight_bytes": fl["client_bytes"],
           "server_flight_segments": fl["server_segments"], "client_flight_segments": fl["client_segments"],
           "client_hello_flight_bytes": fl["hello_bytes"], "client_hello_flight_segments": fl["hello_segments"],
           "client_second_flight_bytes": fl["second_bytes"],
           "client_second_flight_segments": fl["second_segments"],
           "server_flight_mss_segments": fl["server_mss_segments"],
           "client_hello_flight_mss_segments": fl["hello_mss_segments"],
           "client_second_flight_mss_segments": fl["second_mss_segments"],
           "max_segment_bytes": max((n for _, _, n in order), default=0), "version": "",
           "group": "", "hrr": False, "client_hello_bytes": "", "key_shares": "",
           "key_share_bytes": "", "cert_bytes_tls12": "", "alert": "",
           "server_messages": "", "client_messages": ""}
    chs = [b for t, b in cm if t == 1]
    if chs:
        res["client_hello_bytes"] = len(chs[0]) + 4
        ch = parse_client_hello(chs[0])
        res["key_shares"] = "+".join(g for g, _ in ch["key_shares"])
        res["key_share_bytes"] = sum(n for _, n in ch["key_shares"])
    shs = [parse_server_hello(b) for t, b in sm if t == 2]
    if shs:
        res["hrr"] = any(x["hrr"] for x in shs)
        final = [x for x in shs if not x["hrr"]]
        if final:
            res["version"] = final[-1]["version"]
            res["group"] = final[-1]["group"] or ""
        elif shs:
            res["version"] = shs[-1]["version"]
    if res["version"] == "1.2":
        certs = [b for t, b in sm if t == 11]
        if certs:
            res["cert_bytes_tls12"] = len(certs[0]) + 4
        ske = [b for t, b in sm if t == 12]
        if ske and len(ske[0]) >= 3 and ske[0][0] == 3:          # named curve
            res["group"] = TLS_GROUPS.get(struct.unpack(">H", ske[0][1:3])[0], res["group"])
    parts = []
    for who, al in (("server", salerts), ("client", calerts)):
        fatal = [d for lvl, d in al if lvl == 2]
        if fatal:
            parts.append(f"{ALERTS.get(fatal[0], str(fatal[0]))} ({who})")
    res["alert"] = "; ".join(parts)
    res["server_messages"] = " ".join(HS_NAMES.get(t, str(t)) for t, _ in sm)
    res["client_messages"] = " ".join(HS_NAMES.get(t, str(t)) for t, _ in cm)
    res.update(round_trips(res, window))
    return res


def capture_window(run):
    """How the OS that made RUN counts TCP's initial window: "bytes" on macOS (env.txt's host
    line), else "segments" (Linux)."""
    try:
        with open(os.path.join(run, "env.txt")) as f:
            host = next((l for l in f if l.startswith("host:")), "")
    except OSError:
        host = ""
    return "bytes" if "Darwin" in host else "segments"


def load_captures(runs):
    """-> [(run, relative file, index row, analysis)]; key-exchange rows get their server
    certificate ("cert": the index's, or the run's) and its "issuer" (the run's)."""
    out = []
    for run, env in load_env(runs):
        cdir = os.path.join(run, "captures")
        idx = os.path.join(cdir, "index.csv")
        if not os.path.isfile(idx):
            continue
        window = capture_window(run)
        certs, issuer = run_certs(env)
        for row in read_rows(run, idx):
            if row["mode"] == "kem":
                row["cert"], row["issuer"] = row.get("cert") or certs[0], issuer
            else:
                row["cert"], row["issuer"] = "", ""
            p = os.path.join(cdir, row["file"])
            if os.path.isfile(p):
                try:
                    a = analyse_capture(p, window)
                except (struct.error, IndexError, ValueError):
                    a = None
                if a:
                    out.append((run, row["file"], row, a))
    return out

# TCP's initial congestion window (RFC 6928), and the segment size of a 1,500-byte MTU
# with TCP timestamps: a flight of more segments waits a round trip for acknowledgements
INIT_WINDOW, MTU1500_MSS = 10, 1448


def server_segments(a):
    """-> (segments, captured?): the server flight's TCP segments as captured on a path with
    Ethernet-size segments (pqcbench.sh --mtu 1500), else estimated at 1,448-byte segments."""
    if 0 < a["max_segment_bytes"] <= 1460:
        return a["server_flight_segments"], True
    return -(-a["server_flight_bytes"] // MTU1500_MSS), False


def slow_start_rtts(segments, window):
    """Round trips a flight of SEGMENTS waits for acknowledgements in TCP slow start, from a
    congestion window of WINDOW segments that doubles each round trip."""
    extra, sent = 0, window
    while sent < segments:
        window *= 2
        sent += window
        extra += 1
    return extra


def round_trips(a, window="segments"):
    """The handshake's round trips, counted from the capture (not timed), as versions mode's
    [N RTT]: the TCP connect and the HTTP request/response are left out. TLS: 1 for TLS 1.3,
    +1 for a HelloRetryRequest, +1 for TLS 1.2. Window: the round trips TCP slow start adds,
    from an initial window of INIT_WINDOW segments, to the server flight and to the client's
    second flight. How the window is counted depends on the OS, as the network-simulation runs
    showed (MTU 1500, 40 ms):
      "segments" (Linux): the flight's 1,448-byte segments, each captured packet split into
        as many as it needs (on a 1,500-byte-MTU capture, the captured segments); the
        client's window doesn't grow with its ClientHello (Linux grows it only when the window
        limited what was sent)
      "bytes" (macOS): the flight's bytes in 1,448-byte segments; the client's window grows
        by its first flight
    They differ for a flight sent in small packets (wolfSSL: one message per packet).
    Refused handshakes have no count ("")."""
    keys = ("tls_rtts", "server_window_rtts", "client_window_rtts", "handshake_rtts", "extra_rtts",
            "window")
    if not a["version"] or a["alert"] or not a["client_second_flight_bytes"]:
        return dict.fromkeys(keys, "")
    if window == "segments":
        segs = lambda f: a[f + "_mss_segments"]
    else:
        segs = lambda f: -(-a[f + "_bytes"] // MTU1500_MSS)
    tls = 1 + (a["version"] == "1.2") + bool(a["hrr"])
    s_rtts = slow_start_rtts(segs("server_flight"), INIT_WINDOW)
    c_rtts = slow_start_rtts(segs("client_second_flight"),
                             INIT_WINDOW + (segs("client_hello_flight") if window == "bytes" else 0))
    return dict(zip(keys, (tls, s_rtts, c_rtts, tls + s_rtts + c_rtts, tls - 1 + s_rtts + c_rtts,
                           window)))


def rtt_label(a):
    """[N RTT] with what added round trips (h: HelloRetryRequest, 1.2: TLS 1.2, s/c: the
    server/client flight over the initial window), or "-" for a refused handshake."""
    if a["handshake_rtts"] == "":
        return "-"
    why = (["h"] if a["hrr"] else []) + (["1.2"] if a["version"] == "1.2" else []) \
        + ["s"] * a["server_window_rtts"] + ["c"] * a["client_window_rtts"]
    return f"[{a['handshake_rtts']} RTT]" + (f" {'+'.join(why)}" if why else "")


def extra_rtts_cell(rtts):
    """'+0 x12, +1 x4': how many captures had each number of extra round trips."""
    n = defaultdict(int)
    for r in rtts:
        if r != "":
            n[r] += 1
    return ", ".join(f"+{k} x{n[k]}" for k in sorted(n)) or "-"


def analyse_captures(caps, rep, outdir):
    if not caps:
        return
    rep.heading("4. Handshake traffic (packet captures)")
    with open(os.path.join(outdir, "captures_summary.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        cols = ["version", "group", "hrr", "alert", "client_hello_bytes", "key_shares", "key_share_bytes",
                "server_flight_bytes", "client_flight_bytes", "cert_bytes_tls12", "bytes_c2s",
                "bytes_s2c", "packets", "client_messages", "server_messages", "server_flight_segments",
                "client_flight_segments", "max_segment_bytes", "client_second_flight_bytes",
                "client_second_flight_segments", "tls_rtts", "server_window_rtts", "client_window_rtts",
                "handshake_rtts", "extra_rtts", "window"]
        wr.writerow(["file", "mode", "case", "cert", "client", "server", "decryptable"] + cols)
        for _, rel, row, a in caps:
            wr.writerow([rel, row["mode"], row["case"], row["cert"], row["client"], row["server"],
                         row["decryptable"]] + [("yes" if a[c] else "no") if c == "hrr" else a[c] for c in cols])

    rep.para("Handshake sizes in TLS bytes on the wire. Server flight = everything the server sends "
             "before the client's second flight (ServerHello, certificate chain, CertificateVerify, "
             "Finished; plus any HelloRetryRequest; for TLS 1.2 up to ServerHelloDone). Client flight = "
             "ClientHello(s) plus the client's second flight (its certificate and CertificateVerify in "
             "mutual TLS, Finished, and the ~40-byte HTTP request). Alerts show who sent them and are "
             "listed only when sent unencrypted; open the .pcapng in Wireshark to see encrypted ones. "
             "A refusal with no server alert means the server closed the connection without one.",
             note=True)
    by_mode = defaultdict(list)
    for x in caps:
        by_mode[x[2]["mode"]].append(x)
    titles = {"kem": "Key-exchange mode", "mldsa": "ML-DSA mode (mutual TLS)",
              "versions": "Versions mode"}
    for mode in ("kem", "mldsa", "versions"):
        items = by_mode.get(mode)
        if not items:
            continue
        rep.heading(titles[mode], 3)
        rows = []
        for _, rel, row, a in items:
            name = kem_name(row["case"], row["cert"], row["issuer"]) if mode == "kem" else row["case"]
            d = f"{LIB_NAME.get(row['client'], row['client'])} -> {LIB_NAME.get(row['server'], row['server'])}"
            extra = ""
            if mode == "mldsa":
                extra = rel.rsplit("-", 1)[-1].split(".")[0]      # mutual / nocert / untrusted
            neg = f"TLS {a['version']} {a['group']}".strip() if a["version"] else "-"
            rows.append([name + (f" [{extra}]" if extra else ""), d, neg, "yes" if a["hrr"] else "",
                         a["alert"], a["client_hello_bytes"], a["key_share_bytes"],
                         a["server_flight_bytes"], a["client_flight_bytes"], rtt_label(a),
                         "yes" if row["decryptable"] == "yes" else "no"])
        rep.table(["case", "client -> server", "negotiated", "HRR", "alert", "ClientHello B",
                   "key share B", "server flight B", "client flight B", "handshake RTT", "decryptable"],
                  rows, ["l", "l", "l", "l", "l", "r", "r", "r", "r", "l", "l"], collapse=True)

    # the server certificates (cert, issuer), ECDSA first, then in the order captured; versions
    # mode's handshakes use the ECDSA P-256 certificate
    cert_of = lambda row: (row["cert"], row["issuer"]) if row["mode"] == "kem" else ("ec", "openssl")
    rank = {}
    for ck in [("ec", "openssl")] + [cert_of(x[2]) for x in caps]:
        rank.setdefault(ck, len(rank))
    corder = lambda cks: sorted(cks, key=lambda ck: (ck[0] != "ec", rank[ck]))
    order = ["X25519", "P-256", "P-384", "MLKEM512", "MLKEM768", "MLKEM1024",
             "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]
    gorder = lambda gs: [g for g in order if g in gs] + sorted(set(gs) - set(order))
    # handshake size by negotiated group and server certificate (client -> server and server -> client)
    agg = defaultdict(lambda: defaultdict(list))
    for _, rel, row, a in caps:
        if row["mode"] in ("kem", "versions") and a["group"] and not a["alert"] and not a["hrr"] \
                and a["version"] == "1.3" and "mldsa" not in row["case"]:
            k = (a["group"], cert_of(row))
            agg[k]["ch"].append(a["client_hello_bytes"] or 0)
            agg[k]["c2s"].append(a["client_flight_bytes"])
            agg[k]["s2c"].append(a["server_flight_bytes"])
            agg[k]["segs"].append(server_segments(a))
            agg[k]["rtts"].append(a["extra_rtts"])
    mld = defaultdict(list)
    for _, rel, row, a in caps:
        if row["mode"] == "mldsa" and rel.endswith(("-mutual.pcapng", "-mutual.pcap")) and not a["alert"]:
            mld[row["case"].rsplit("-", 2)[0]].append((a["client_flight_bytes"], a["server_flight_bytes"],
                                                       server_segments(a), a["extra_rtts"]))
    # server flight in segments (median), and the captures' extra round trips
    def segs_cells(segs, rtts):
        n = [s for s, _ in segs]
        est = "" if all(c for _, c in segs) else " (est.)"
        return [f"{int(statistics.median(n))}{est}", extra_rtts_cell(rtts)]
    seg_note = ("Round trips are counted from the captures, not timed, so they hold for any network "
                "RTT. Handshake RTT (per capture) is versions mode's [N RTT], without the TCP connect "
                "and the request/response: TLS 1.3 = 1, +1 for a HelloRetryRequest, +1 for TLS 1.2, "
                "and +1 for each doubling TCP slow start needs to send a flight larger than the "
                f"initial window of {INIT_WINDOW} segments (s: server flight, c: the client's second "
                "flight, whose window has grown by its first). Extra round trips: captures by round "
                "trips beyond 1. The window is counted as the run's OS does, as the network-simulation "
                f"runs (MTU 1500, 40 ms) showed: Linux in segments (each packet as the {MTU1500_MSS}-"
                f"byte segments it needs), macOS in bytes (the flight's bytes in {MTU1500_MSS}-byte "
                "segments). They differ for a flight sent in small packets (wolfSSL: one message per "
                "packet). Server flight segments: as captured on a 1,500-byte-MTU path (pqcbench.sh "
                f"--mtu 1500), else (est.) the flight in {MTU1500_MSS}-byte segments.")
    if agg or mld:
        rep.heading("Handshake size summary", 3)
        rep.para(seg_note, note=True)
    if agg:
        cks = corder({ck for _, ck in agg})
        keys = [(g, ck) for g in gorder({g for g, _ in agg}) for ck in cks if (g, ck) in agg]
        many = len(cks) > 1
        if many:
            rep.para("TLS 1.3 handshake size by key-exchange group and server certificate (median over "
                     "captures; no HelloRetryRequest):", finding=True)
        else:
            rep.para(f"TLS 1.3 handshake size by key-exchange group (median over captures; "
                     f"{cert_desc(*cks[0])} server certificate, no HelloRetryRequest):", finding=True)
        rep.table(["group"] + (["server certificate"] if many else []) +
                  ["captures", "ClientHello B", "client flight B", "server flight B",
                   "server flight segments", "extra round trips"],
                  [[g] + ([cert_desc(*ck)] if many else []) +
                   [len(agg[g, ck]["c2s"]), int(statistics.median(agg[g, ck]["ch"])),
                    int(statistics.median(agg[g, ck]["c2s"])), int(statistics.median(agg[g, ck]["s2c"]))]
                   + segs_cells(agg[g, ck]["segs"], agg[g, ck]["rtts"]) for g, ck in keys],
                  ["l"] * (1 + many) + ["r"] * 6, finding=True)
    if mld:
        rep.para("\nMutual TLS with ML-DSA certificates, handshake size by chain profile (median; both "
                 "flights carry a certificate and a CertificateVerify):", finding=True)
        rep.table(["profile (CA-leaf)", "captures", "client flight B", "server flight B",
                   "server flight segments", "extra round trips"],
                  [[p, len(v), int(statistics.median([x[0] for x in v])),
                    int(statistics.median([x[1] for x in v]))]
                   + segs_cells([x[2] for x in v], [x[3] for x in v])
                   for p, v in sorted(mld.items())], finding=True)
    # each client's ClientHello and each server's first flight, per group and server certificate
    # (key-exchange mode: every client offers only the group under test), e.g. one rustls
    # provider vs another
    by_cli = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    by_srv = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for _, rel, row, a in caps:
        if row["mode"] == "kem" and a["group"] and not a["alert"] and not a["hrr"] and a["version"] == "1.3":
            by_cli[row["client"]][cert_of(row)][a["group"]].append(a["client_hello_bytes"] or 0)
            by_srv[row["server"]][cert_of(row)][a["group"]].append(a["server_flight_bytes"])
    if len(by_cli) > 1 or len(by_srv) > 1:
        groups = gorder({g for d in by_cli.values() for c in d.values() for g in c})
        cks = corder({ck for d in by_cli.values() for ck in d})
        many = len(cks) > 1
        libs = lambda d: [l for l in LIBS if l in d] + sorted(set(d) - set(LIBS))
        cell = lambda v: str(int(statistics.median(v))) if v else "-"

        def table(by, who):
            rep.table([who] + (["server certificate"] if many else []) + groups,
                      [[LIB_NAME.get(l, l)] + ([cert_desc(*ck)] if many else [])
                       + [cell(by[l][ck].get(g)) for g in groups]
                       for l in libs(by) for ck in cks if ck in by[l]],
                      ["l"] * (1 + many) + ["r"] * len(groups), finding=True)
        if many:
            rep.para("\nKey-exchange mode, ClientHello bytes by client library, server certificate and "
                     "group (median over its captures; every client offers only the group under test, "
                     "with some s2n-tls client policies depending on the certificate):", finding=True)
        else:
            rep.para("\nKey-exchange mode, ClientHello bytes by client library and group (median over "
                     "its captures; every client offers only the group under test):", finding=True)
        table(by_cli, "client")
        if many:
            rep.para("\nKey-exchange mode, server flight bytes by server library, server certificate and "
                     "group (median; ServerHello to Finished, each certificate the same for every "
                     "server):", finding=True)
        else:
            rep.para("\nKey-exchange mode, server flight bytes by server library and group (median; "
                     "ServerHello to Finished, with the same certificate for every server):", finding=True)
        table(by_srv, "server")

# --------------------------------------------------------------------------
# Charts (optional, matplotlib)
# --------------------------------------------------------------------------
INK, INK2, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
LIB_COLOR = {"openssl": "#2a78d6", "wolfssl": "#eb6834",        # categorical slots 1, 2, 3, 4
             "s2n": "#1baf7a", "awslc": "#1baf7a", "rustls": "#eda100"}
# rustls_<provider>, in provider order (register_libs): amber as before, then hues apart
# from slots 1-3
RUSTLS_COLORS = ["#eda100", "#8a5cc2", "#d1477a", "#a5194f", "#2c9fa6", "#16626a", "#8a6a4a", "#6b6b6b"]
DIR_COLOR = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]        # slots 1-4 (validated)
# more than four directions: hue = client library, shade = server library (OpenSSL dark,
# wolfSSL base, s2n-tls light, rustls darkest); every shade has >= 2:1 contrast against SURFACE.
# More than four libraries (several rustls providers): shades made from the client's hue.
DIR_SHADES = {"openssl": ("#1b4e8b", "#2a78d6", "#6aa0e2", "#0f2c52"),
              "wolfssl": ("#994422", "#eb6834", "#f19571", "#6b2f17"),
              "s2n": ("#12724f", "#1baf7a", "#5fc7a2", "#0b4a33"),
              "rustls": ("#9a6900", "#eda100", "#f3c35c", "#5c3e00")}
SHADE_SLOT = {"openssl": 0, "wolfssl": 1, "s2n": 2, "rustls": 3}


def _shade_key(l):
    """DIR_SHADES entry of LIB (a lone rustls provider uses rustls's), or None."""
    if l in DIR_SHADES:
        return l
    if l in RUSTLS_PROVIDER and sum(x in RUSTLS_PROVIDER for x in RUN_LIBS) == 1:
        return "rustls"
    return None


def _shade(color, i, n):
    """Shade I of N of COLOR, from darker (0) to lighter (N-1)."""
    t = -0.45 + 0.8 * i / max(1, n - 1)
    rgb = [int(color[k:k + 2], 16) for k in (1, 3, 5)]
    rgb = [c + (255 - c) * t if t > 0 else c * (1 + t) for c in rgb]
    return "#" + "".join(f"{round(c):02x}" for c in rgb)


def dir_color(d):
    if len(DIRECTIONS) <= 4:
        return DIR_COLOR[DIRECTIONS.index(d)]
    if len(RUN_LIBS) <= 4 and all(_shade_key(l) for l in RUN_LIBS):
        return DIR_SHADES[_shade_key(d[0])][SHADE_SLOT[_shade_key(d[1])]]
    return _shade(LIB_COLOR.get(d[0], MUTED), RUN_LIBS.index(d[1]), len(RUN_LIBS))


def _bar_layout():
    """(bar height, gap, offset of the first bar) for one group of direction bars."""
    n = len(DIRECTIONS)
    if n <= 4:
        return 0.19, 0.02, 0.3
    if n <= 16:
        h, gap = 0.78 / n - 0.01, 0.01
    else:
        h, gap = 0.78 / n * 0.8, 0.78 / n * 0.2
    return h, gap, (n - 1) / 2 * (h + gap)


def _group_height():
    """Inches per group of direction bars."""
    n = len(DIRECTIONS)
    return 0.62 if n <= 4 else 1.15 if n <= 16 else 0.072 * n


def _legend_rows():
    # beyond 16 directions (short labels): one row per client library
    n = len(DIRECTIONS)
    ncol = 4 if n <= 4 else 3 if n <= 16 else len(RUN_LIBS)
    return ncol, -(-n // ncol)


def _style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.tick_params(colors=INK2, labelsize=9, length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _legend_label(d):
    """Legend entry of direction D: library names, or beyond 16 directions the short labels."""
    return dir_label(d, full=len(DIRECTIONS) <= 16)


def _key_height():
    """Inches under the title for the key to the short labels (beyond 16 directions)."""
    return 0.4 if len(DIRECTIONS) > 16 else 0


def _fig_header(fig, title):
    """Title at most 0.3 in from the top (tall charts), plus the short labels' key if used."""
    hgt = fig.get_size_inches()[1]
    fig.text(0.015, 1 - min(0.025 * hgt, 0.3) / hgt, title, color=INK, fontsize=12, ha="left", va="top")
    if _key_height():
        key = "client -> server: " + ", ".join(f"{LIB_SHORT[l]} = {LIB_NAME[l]}" for l in RUN_LIBS)
        fig.text(0.015, 1 - 0.5 / hgt, textwrap.fill(key, 115), color=INK2, fontsize=8.5,
                 ha="left", va="top")


def _fig_legend(fig, ax, y, ncol):
    """Figure-wide legend under the title (directions in presentation order)."""
    h, l = ax.get_legend_handles_labels()
    order = sorted(range(len(l)), key=lambda i: [_legend_label(d) for d in DIRECTIONS].index(l[i]))
    fig.legend([h[i] for i in order], [l[i] for i in order], loc="upper left",
               bbox_to_anchor=(0.01, y if len(DIRECTIONS) <= 4 else
                               1 - (0.55 + _key_height()) / fig.get_size_inches()[1]),
               ncol=ncol, frameon=False, fontsize=8.5, labelcolor=INK2, handlelength=1.2,
               columnspacing=1.2)


def plot_primitives(paired_by_lib, outdir, plt):
    if any(l != "wolfssl" and pl for l, pl in paired_by_lib.items()):
        return _plot_primitives3(paired_by_lib, outdir, plt)
    paired = paired_by_lib.get("wolfssl")
    if not paired:
        return None
    labels = [f"{a}  {o}" for (a, o), _, _, _ in paired]
    ratios = [r for _, _, _, r in paired]
    h = max(3.0, 0.28 * len(paired) + 1.4)
    fig, ax = plt.subplots(figsize=(8.5, h), facecolor=SURFACE)
    _style(ax)
    y = list(range(len(paired)))[::-1]
    logs = [math.log2(r) for r in ratios]
    colors = [LIB_COLOR["wolfssl"] if r >= 1 else LIB_COLOR["openssl"] for r in ratios]
    ax.barh(y, logs, height=0.62, color=colors, left=0)
    ax.axvline(0, color=AXIS, linewidth=1)
    lim = max(1.0, max(abs(v) for v in logs) * 1.25)
    ax.set_xlim(-lim, lim)
    ticks = [t for t in range(-6, 7) if abs(t) <= lim]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{2 ** abs(t):g}x" if t else "same" for t in ticks])
    ax.set_yticks(y)
    ax.set_yticklabels(labels, color=INK)
    for yi, lv, r in zip(y, logs, ratios):
        txt = f"{r:.2f}x" if r >= 1 else f"{1 / r:.2f}x"
        ax.text(lv + (0.05 * lim if lv >= 0 else -0.05 * lim), yi, txt, va="center",
                ha="left" if lv >= 0 else "right", fontsize=8, color=INK2)
    ax.set_xlabel("<- OpenSSL faster        throughput ratio (log scale)        wolfSSL faster ->",
                  color=INK2, fontsize=9)
    ax.set_title("Primitive throughput: wolfSSL vs OpenSSL", color=INK, fontsize=12,
                 loc="left", pad=12)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=LIB_COLOR["openssl"], label="OpenSSL faster"),
                       Patch(color=LIB_COLOR["wolfssl"], label="wolfSSL faster")],
              loc="lower right", frameon=False, fontsize=9, labelcolor=INK2)
    fig.tight_layout()
    path = os.path.join(outdir, "primitives_ratio.png")
    fig.savefig(path, dpi=160, facecolor=SURFACE)
    plt.close(fig)
    return path


def _plot_primitives3(paired_by_lib, outdir, plt):
    """Grouped bars: one per library per operation, log2 throughput ratio vs OpenSSL."""
    libs = [l for l in prim_libs() if l != "openssl" and paired_by_lib.get(l)]
    ratio = {(l, p[0]): p[3] for l in libs for p in paired_by_lib[l]}
    keys = sorted({k for _, k in ratio}, key=sort_key)
    n = len(keys)
    # more than three libraries (several rustls providers): taller groups, legend below
    many = len(libs) > 3
    per = 0.13 * len(libs) if many else 0.5
    fig, ax = plt.subplots(figsize=(8.5, max(3.0, per * n + (2.4 if many else 1.6))), facecolor=SURFACE)
    _style(ax)
    bar_h = 0.8 / len(libs)
    logs = [math.log2(r) for r in ratio.values()]
    lim = max(1.0, max(abs(v) for v in logs) * 1.3)
    for gi, k in enumerate(keys):
        for li, l in enumerate(libs):
            r = ratio.get((l, k))
            if r is None:
                continue
            yy = (n - 1 - gi) + 0.4 - bar_h / 2 - li * bar_h
            lv = math.log2(r)
            ax.barh(yy, lv, height=bar_h * 0.9, color=LIB_COLOR[l])
            ax.text(lv + (0.04 * lim if lv >= 0 else -0.04 * lim), yy,
                    f"{r:.2f}x" if r >= 1 else f"{1 / r:.2f}x", va="center",
                    ha="left" if lv >= 0 else "right", fontsize=7, color=INK2)
    ax.axvline(0, color=AXIS, linewidth=1)
    ax.set_xlim(-lim, lim)
    ticks = [t for t in range(-6, 7) if abs(t) <= lim]
    ax.set_xticks(ticks)
    ax.set_xticklabels([f"{2 ** abs(t):g}x" if t else "same" for t in ticks])
    ax.set_yticks([n - 1 - i for i in range(n)])
    ax.set_yticklabels([f"{a}  {o}" for a, o in keys], color=INK)
    ax.set_ylim(-0.6, n - 0.4)
    ax.set_xlabel("<- OpenSSL faster        throughput ratio vs OpenSSL (log scale)        library faster ->",
                  color=INK2, fontsize=9)
    # (three or more: the legend names them)
    ax.set_title("Primitive throughput: " + " and ".join(LIB_NAME[l] for l in libs) + " vs OpenSSL"
                 if len(libs) <= 2 else "Primitive throughput vs OpenSSL",
                 color=INK, fontsize=12, loc="left", pad=12)
    from matplotlib.patches import Patch
    handles = [Patch(color=LIB_COLOR[l], label=f"{LIB_NAME[l]} / OpenSSL") for l in libs]
    if many:
        fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, fontsize=9,
                   labelcolor=INK2)
        fig.tight_layout(rect=(0, 0.8 / fig.get_size_inches()[1], 1, 1))
    else:
        ax.legend(handles=handles, loc="lower right", frameon=False, fontsize=9, labelcolor=INK2)
        fig.tight_layout()
    path = os.path.join(outdir, "primitives_ratio.png")
    fig.savefig(path, dpi=160, facecolor=SURFACE)
    plt.close(fig)
    return path


def plot_directions(results, suite, title, outdir, plt):
    keys = [k for k in results if k[0] == suite and (results[k]["complete"] or results[k]["blocks"])]
    if not keys:
        return None
    n = len(keys)
    ncol, lrows = _legend_rows()
    top = 0.95 + 0.2 * (lrows - 1) + _key_height()
    per = _group_height()
    fig, ax = plt.subplots(figsize=(8.5, max(3.0, per * n + 0.65 + top)), facecolor=SURFACE)
    _style(ax)
    bar_h, gap, off = _bar_layout()
    seen = set()
    for gi, k in enumerate(keys):
        base = (n - 1 - gi)
        for di, d in enumerate(DIRECTIONS):
            s = results[k]["desc"].get(d)
            if s is None:
                continue
            yy = base + off - di * (bar_h + gap)
            ax.barh(yy, s["median"], height=bar_h, color=dir_color(d),
                    label=_legend_label(d) if d not in seen else None)
            seen.add(d)
            ax.plot([s["p25"], s["p75"]], [yy, yy], color=INK2, linewidth=1)
    ax.set_yticks([n - 1 - i for i in range(n)])
    if len(DIRECTIONS) > 16:          # (default 5% margins are inches on a tall chart)
        ax.set_ylim(-0.5, n - 0.5)
    ax.set_yticklabels([k[1] for k in keys], color=INK)
    ax.set_xlabel("median handshake time, ms (line = interquartile range)", color=INK2, fontsize=9)
    # title and legend span the whole figure, so long row labels can't push them off the edge
    _fig_header(fig, title)
    _fig_legend(fig, ax, 0.93, ncol)
    fig.tight_layout(rect=(0, 0, 1, 1 - top / fig.get_size_inches()[1]))
    path = os.path.join(outdir, f"handshakes_{suite}.png")
    fig.savefig(path, dpi=160, facecolor=SURFACE)
    plt.close(fig)
    return path


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Analyse pqcbench.sh results.")
    ap.add_argument("runs", nargs="*", help="run directories (default: newest in ./pqcbench-results)")
    ap.add_argument("--out", help="output directory (default: <first run>/analysis)")
    ap.add_argument("--bootstrap", type=int, default=2000, help="bootstrap resamples (0 = off)")
    ap.add_argument("--no-plots", action="store_true", help="don't draw charts")
    ap.add_argument("--all-primitives", action="store_true",
                    help="also list primitives only one library measured")
    ap.add_argument("--rtt", type=float, default=0.0,
                    help="project version/downgrade timings onto a link with this round-trip time (ms)")
    ap.add_argument("--markdown", nargs="?", const="", metavar="FILE",
                    help="also write a formatted Markdown report (contents, key findings, test setup, "
                         "embedded charts) to FILE (default: <out>/results.md)")
    args = ap.parse_args()

    runs = find_runs(args.runs)
    outdir = os.path.abspath(args.out or os.path.join(runs[0], "analysis"))
    os.makedirs(outdir, exist_ok=True)
    rep = Report()
    rep.para("Runs: " + ", ".join(os.path.relpath(r) for r in runs))
    envs = load_env(runs)
    fips = fips_mode(envs)
    if fips == "on":
        rep.para("FIPS mode (pqcbench.sh --fips): the libraries' FIPS builds with FIPS-approved algorithms "
                 "only (no X25519; FIPS-compliant s2n-tls policies). Their start-up includes the FIPS "
                 "modules' integrity checks and self-tests; see Test setup for each module.")
    elif fips == "mixed":
        print("\nwarning: the runs mix FIPS (--fips) and non-FIPS builds; pooled samples aren't comparable")
        rep.para("Warning: the pooled runs mix FIPS-mode (--fips) and regular runs, which use different "
                 "library builds; see Test setup.")
    netsim, ns = netsim_settings(envs)
    if netsim == "on":
        rep.para(f"Network simulation (pqcbench.sh --mtu/--rtt/--bw): {ns['line']}. Handshake times "
                 "include the simulated round trips: compare them only with runs made with the same "
                 "settings.")
        if args.rtt and ns["rtt"]:
            print(f"\nwarning: --rtt {args.rtt:g} ignored: these runs already had a {ns['rtt']:g} ms round trip")
            args.rtt = 0.0
    elif netsim == "mixed":
        print("\nwarning: the runs mix network-simulation settings (--mtu/--rtt/--bw); pooled timings "
              "aren't comparable")
        rep.para("Warning: the pooled runs mix network-simulation settings (pqcbench.sh --mtu/--rtt/--bw, "
                 "env.txt's netsim line); their timings aren't comparable.")
    remote, rs = remote_settings(envs)
    if remote == "on":
        rtt_txt = f"{rs['measured']:.1f} ms" if rs["measured"] else "not measured"
        rep.para(f"Remote servers (pqcbench.sh --remote): {rs['line']}; round trip {rtt_txt}. Handshake "
                 "times include that network path's round trips: compare them only with runs over the "
                 "same path.")
        if args.rtt:
            print(f"\nwarning: --rtt {args.rtt:g} ignored: these runs already crossed a real network path")
            args.rtt = 0.0
    elif remote == "mixed":
        print("\nwarning: the runs mix network paths (--remote with other servers, or with local runs); "
              "pooled timings aren't comparable")
        rep.para("Warning: the pooled runs mix network paths (pqcbench.sh --remote against different "
                 "servers, or together with local runs; env.txt's remote line); their timings aren't "
                 "comparable.")
    issuers = list(dict.fromkeys(run_certs(env)[1] for _, env in envs))
    if len(issuers) > 1:
        names = ", ".join(LIB_NAME.get(i, i) for i in issuers)
        print(f"\nwarning: the runs' key-exchange server certificates come from different issuers ({names}, "
              "pqcbench.sh --cert-issuer); their measurements are kept apart")
        rep.para(f"Warning: the pooled runs' key-exchange server certificates come from different issuers "
                 f"({names}, pqcbench.sh --cert-issuer); measurements with certificates not issued by "
                 "OpenSSL are named for their issuer and kept apart; see Test setup.")
    # one library per rustls crypto provider, also in runs that called it just "rustls"
    register_libs(envs)

    prims = load_primitives(runs)
    paired = analyse_primitives(prims, rep, outdir, args.all_primitives)
    startup = load_startup(runs)
    hs = load_handshakes(runs)
    vout, vsamp = load_versions(runs)
    set_libraries({l for cells in hs.values() for d in cells for l in d}
                  | {l for k in list(vout) + list(vsamp) for l in k[1:]})
    entropy = {"s2n": awslc_entropy(envs)} | {l: awslc_entropy(envs, l) for l in RUSTLS_PROVIDER}
    policies = load_kem_policies(runs)
    results = analyse_handshakes(hs, startup, args.bootstrap, rep, outdir, mldsa_group(runs), entropy, policies)
    inproc, inproc_init = load_inproc(runs)
    analyse_inproc(inproc, inproc_init, hs, startup, rep, outdir, entropy)
    ccosts = analyse_cert_costs(hs, inproc, rep, outdir, policies)
    rtrips = (netsim == "on" and analyse_round_trips(inproc, hs, startup, ns, rep, outdir)) or \
             (remote == "on" and analyse_round_trips(inproc, hs, startup, rs, rep, outdir))
    vchart = analyse_versions(vout, vsamp, args.bootstrap, args.rtt, rep, outdir)
    caps = load_captures(runs)
    analyse_captures(caps, rep, outdir)

    charts = []
    if not args.no_plots:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            charts = [plot_primitives(paired, outdir, plt),
                      plot_directions(results, "kem", "Key-exchange handshakes by direction (client -> server)",
                                      outdir, plt),
                      plot_directions(results, "mldsa", "Mutual-TLS ML-DSA handshakes by direction "
                                      "(client -> server)", outdir, plt),
                      plot_versions(vchart, outdir, plt)]
            charts = [c for c in charts if c]
        except ImportError:
            print("\n(matplotlib not installed: charts skipped; pip install matplotlib)")

    tag = " (FIPS mode)" if fips == "on" else ""
    rep.write(os.path.join(outdir, "report.md"), "pqc-bench analysis" + tag)
    written = ["report.md"]
    if args.markdown is not None:
        mdpath = os.path.abspath(args.markdown or os.path.join(outdir, "results.md"))
        settings = [("analysis: bootstrap resamples", str(args.bootstrap)),
                    ("analysis: projected RTT", f"{args.rtt:g} ms" if args.rtt else "off")]
        rep.write_markdown(mdpath, "pqc-bench results" + tag, envs, charts, settings)
        written.append(os.path.relpath(mdpath, outdir))
    print(f"\nWritten to {os.path.relpath(outdir)}/: {', '.join(written)}, primitives_comparison.csv, "
          f"handshake_directions.csv, handshake_effects.csv"
          + (", versions_comparisons.csv" if vout else "")
          + (", captures_summary.csv" if caps else "")
          + (", cert_costs.csv" if ccosts else "")
          + (", round_trips.csv" if rtrips else "")
          + ("".join(f", {os.path.basename(c)}" for c in charts)))


if __name__ == "__main__":
    main()
