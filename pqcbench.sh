#!/bin/sh
# =============================================================================
# pqcbench.sh — OpenSSL, wolfSSL, s2n-tls and rustls: PQC performance and interoperability
#
# Portable POSIX sh (tested with dash and bash). No bash/zsh features used.
#
# KEM MODE (--mlkem; default when no mode flag is given)
#   Primitives: raw KEM / ECDH / RSA throughput
#       OpenSSL -> `openssl speed`, wolfSSL -> wolfcrypt/benchmark/benchmark,
#       AWS-LC (s2n-tls's libcrypto) -> `bssl speed`, rustls -> `pqc-rustls speed`
#       (its crypto provider through rustls's own interfaces)
#   Handshakes: times every individual TLS 1.3 handshake for each key-exchange
#       group across the full client x server matrix of the libraries found
#       (OpenSSL, wolfSSL and, when built, s2n-tls and rustls: up to sixteen
#       directions), e.g. with s2n-tls:
#         openssl -> openssl   openssl -> wolfssl   openssl -> s2n
#         wolfssl -> openssl   wolfssl -> wolfssl   wolfssl -> s2n
#         s2n -> openssl       s2n -> wolfssl       s2n -> s2n
#       The server certificate is the same for every pair and group (ECDSA
#       P-256 by default), so the key-exchange group is the only variable;
#       --cert times the matrix once per certificate (ML-DSA ones too), each
#       group's certificates one after another. Pairs that can't pin a group
#       or use a certificate are skipped (see the GROUP TABLE in
#       libs/wolfssl.sh and the POLICY TABLE in libs/s2n.sh; rustls: groups or
#       ML-DSA levels its provider lacks), or with --pure-pq fall back to a
#       hybrid, then a classical group.
#
# ML-DSA MODE (--mldsa)
#   Primitives: ML-DSA-44/65/87 keygen/sign/verify vs ECDSA, Ed25519, RSA.
#   Interop checks, each recorded as PASS / FAIL / SKIP:
#     keys    OpenSSL keys in all three private-key encodings (seed-priv,
#             seed-only, priv-only) decoded and used by wolfSSL; wolfSSL keys
#             decoded and used by OpenSSL; public keys (SPKI) both ways
#     sigs    sign with one library, verify with the other (pure ML-DSA,
#             empty context), plus tampered-signature rejection both ways
#     certs   CA + server + client chains issued by EACH library, verified by
#             both (with EKU purpose checks), plus rejection under an
#             untrusted CA; profiles 44, 65, 87 and a mixed 87->44 chain
#     tls     mutual TLS (server AND client present ML-DSA certs) in every
#             client/server direction for each chain producer, plus negative
#             tests: client without a certificate and untrusted server chain
#             must be refused. Successful mutual-TLS pairs are also timed.
#             s2n-tls takes part when it supports MLDSA_GROUP (the default,
#             MLKEM768, it doesn't: set MLDSA_GROUP=X25519MLKEM768, or use
#             --pure-pq to give its pairs a fallback group). With
#             MLDSA_GROUP=MLKEM1024 the s2n client joins only ML-DSA-87
#             chains (policy cnsa_2); its other profiles are skipped.
#             rustls takes part when its provider has MLDSA_GROUP and the
#             chain's ML-DSA levels (aws-lc-rs); it skips wolfSSL-issued
#             chains if they lack a subjectAltName (wolfSSL without
#             CPPFLAGS=-DWOLFSSL_ALT_NAMES), since rustls never matches the CN.
#   Keys, signatures and certificates compare OpenSSL with wolfSSL only. The
#   wolfSSL side uses a small helper program that this script compiles against
#   your wolfSSL build (needs a C compiler).
#
# VERSIONS MODE (--versions)
#   TLS version negotiation and downgrade: 16 scenarios, each run in every
#   client/server direction. Each fixes what the two sides allow (TLS 1.2,
#   1.3 or 1.2-1.3; classical, hybrid or ML-KEM-1024-only groups; ECDSA or ML-DSA
#   certificate). The outcome (negotiated version and group, or refusal) is
#   checked against what should happen, flagging HelloRetryRequests and
#   connections where post-quantum protection was lost. Every case is then
#   timed, including time-to-refusal, and the script prints what negotiation,
#   downgrade and HRR cost relative to the reference scenarios.
#
# Usage:
#   ./setup.sh                                          (once: fetches and builds every library here)
#   ./pqcbench.sh [options]                             (wolfSSL in ./wolfssl, s2n-tls in ./s2n-tls,
#                                                        rustls in ./rustls-tools)
#   WOLFSSL_DIR=~/src/wolfssl ./pqcbench.sh [options]   (wolfSSL elsewhere)
#   S2N_DIR=~/src/s2n-tls ./pqcbench.sh [options]       (s2n-tls elsewhere)
#   ./pqcbench.sh --rustls-provider ring [options]      (rustls with another crypto provider)
#
# Options:
#   --mlkem               KEM mode (the default when no mode flag is given)
#   --mldsa               ML-DSA mode
#   --versions            TLS version negotiation/downgrade mode
#                         Mode flags combine: --mlkem --mldsa runs both.
#   --all                 all three modes
#   -n, --iterations N    timed handshakes per pair in KEM mode (default 100)
#   --mldsa-iterations N  timed mutual-TLS handshakes per pair (default 20)
#   --groups "A B C"      KEM groups to test (OpenSSL names, see GROUPS below)
#   --cert "A B …"        KEM mode server certificates, each timed over the whole
#                         matrix (default ec): ec (ECDSA P-256), mldsa44,
#                         mldsa65, mldsa87, or a mixed chain mldsa<CA>-<leaf>
#                         such as mldsa87-44 (ML-DSA-87 CA, ML-DSA-44 leaf);
#                         all = ec mldsa44 mldsa65 mldsa87 mldsa87-44
#   --cert-issuer I       who issues the KEM mode certificates: openssl
#                         (default) or wolfssl (the wolfSSL helper of ML-DSA
#                         mode; needs wolfSSL with --enable-certgen)
#   --mldsa-profiles "…"  chain profiles (default "44 65 87 87-44"; CA-leaf)
#   --versions-iterations N  timed runs per case in versions mode (default 20)
#   --versions-scenarios "…" subset of versions scenarios (default: all)
#   --capture             also capture every checked handshake (pcapng +
#                         session keys + decoded transcript) for Wireshark
#   --primitives-only     only the speed benchmarks
#   --handshakes-only     skip the speed benchmarks
#   --no-s2n              leave s2n-tls out even if it is built (--no-<library>
#                         for any optional library in libs/)
#   --pure-pq             pure ML-KEM key exchange wherever a pair supports it:
#                         KEM mode tests only the pure ML-KEM groups, and ML-DSA
#                         mode needs a pure MLDSA_GROUP. A pair that can't use
#                         the group falls back to a hybrid, then a classical
#                         group, and the summaries note it. Versions mode is
#                         unchanged (its scenarios set their own groups).
#   --inproc              also time each key-exchange and mutual-TLS pair with
#                         the hsloop clients (setup.sh builds them in
#                         hsloop/bin): all handshakes of a pair in one client
#                         process, so process and library start-up are measured
#                         once (init_ms) instead of in every sample. Runs
#                         alongside the per-process timing; versions mode is
#                         not covered.
#   --fips                FIPS mode: the FIPS builds from `setup.sh --fips`
#                         (OpenSSL with its FIPS provider and fips=yes,
#                         wolfSSL FIPS Ready, s2n-tls on AWS-LC FIPS, rustls on
#                         aws-lc-rs's FIPS module) and FIPS-approved choices
#                         only: no X25519, FIPS-compliant s2n-tls policies. Each
#                         library's FIPS mode is checked before the run.
#                         Versions mode is skipped (its scenarios are built on
#                         X25519). See FIPS MODE below.
#   --rustls-provider P   rustls's crypto provider: aws-lc-rs (default), ring,
#                         graviola, graviola-pq, rustcrypto, rustcrypto-pq,
#                         libcrux-pq or wolfcrypt (setup.sh builds one
#                         pqc-rustls per provider; the -pq ones are this
#                         project's, see README.md). Groups and ML-DSA levels
#                         the provider lacks are skipped with a reason. --fips
#                         needs aws-lc-rs. A list ("aws-lc-rs,ring") or "all"
#                         (every provider built) runs them side by side, each
#                         as its own library rustls_<provider> (dashes become
#                         underscores: rustls_aws_lc_rs) in the client x server
#                         matrix, so providers also meet each other.
#   --mtu N               network simulation (netsim.sh, needs root: sudo asks
#                         once): the loopback MTU becomes N (1500 for Ethernet),
#                         so flights are sent as real-size segments
#   --rtt MS              network simulation: a round-trip time of MS ms on the
#                         benchmark's ports (40 is a typical Internet path),
#                         calibrated so a TCP connect takes MS; implies
#                         --mtu 1500 unless --mtu is given. Lowers the default
#                         iterations to 20 / 10 / 5 (key exchange / ML-DSA /
#                         versions): every sample now costs several round trips
#   --bw RATE             network simulation: a bandwidth limit per direction
#                         (e.g. 10mbit; kbit, mbit or gbit); implies --mtu 1500
#                         unless --mtu is given. See NETWORK SIMULATION below.
#   --remote [USER@]HOST  split-host mode: every TLS server runs on HOST, which
#                         this script drives over one SSH connection, and the
#                         clients here connect to HOST directly. See REMOTE
#                         SERVERS below.
#   -h, --help
#
# Environment:
#   OPENSSL        openssl binary (needs 3.5+; default: ./openssl/openssl-install/
#                  bin/openssl next to this script if setup.sh built it, else
#                  openssl on PATH)
#   WOLFSSL_DIR    wolfSSL source/build dir (for examples, benchmark, helper);
#                  defaults to ./wolfssl next to this script if it's configured
#                  (./wolfssl-fips with --fips)
#   WOLF_CLIENT / WOLF_SERVER / WOLF_BENCH   override individual binaries
#   S2N_DIR        s2n-tls source dir with a CMake build in build/ (s2nc, s2nd;
#                  build-fips/ with --fips); defaults to ./s2n-tls next to this
#                  script if it's built. Without it the run covers OpenSSL and
#                  wolfSSL only.
#   S2N_CLIENT / S2N_SERVER   override the s2nc / s2nd binaries
#   BSSL           AWS-LC's bssl for primitive benchmarks (default:
#                  ./aws-lc/aws-lc-install/bin/bssl next to this script;
#                  ./aws-lc/aws-lc-fips-install/bin/bssl with --fips)
#   HSLOOP_DIR     directory with hsloop-openssl, hsloop-wolfssl, hsloop-s2n,
#                  hsloop-rustls-<provider> (default ./hsloop/bin next to this
#                  script; with --fips hsloop-wolfssl-fips, hsloop-s2n-fips and
#                  hsloop-rustls-aws-lc-rs-fips stand in for the others)
#   HSLOOP_OPENSSL / HSLOOP_WOLFSSL / HSLOOP_S2N / HSLOOP_RUSTLS   override individual clients
#                  (HSLOOP_RUSTLS: with a single --rustls-provider)
#   RUSTLS_PROVIDER  same as --rustls-provider
#   RUSTLS_BIN     pqc-rustls binary (default ./rustls-tools/bin/pqc-rustls-<provider>
#                  next to this script; with a single --rustls-provider); without it
#                  the run leaves rustls out
#   OPENSSL_FIPS_DIR  --fips: install dir of the OpenSSL FIPS provider, with
#                  lib/ossl-modules/ and ssl/openssl-fips.cnf (default
#                  ./openssl-fips/openssl-fips-install next to this script)
#   WARMUP         untimed handshakes before each timed series (default 5)
#   SPEED_SECONDS  seconds per `openssl speed` algorithm / `bssl speed` test /
#                  `pqc-rustls speed` operation (default 3)
#   HS_TIMEOUT     per-handshake timeout in seconds (default 10)
#   BASE_PORT      first TCP port to use (default 14433)
#   MLDSA_KEY_FORMAT  if set, re-encode OpenSSL-made ML-DSA TLS keys via
#                  `-provparam ml-dsa.output_formats=<value>`
#   MLDSA_GROUP    key-exchange group for ML-DSA mode handshakes (MLKEM768)
#   CC, HELPER_CFLAGS, HELPER_LIBS   compiler/flags for the wolfSSL helper
#                  (CC may include arguments; SDKROOT etc. pass through as-is)
#   MLDSA_HELPER   use a prebuilt helper instead of compiling one
#   CAPTURE_IFACE  loopback interface for --capture (default lo0 on macOS, lo elsewhere)
#                  (with --remote: the interface towards HOST)
#   CAPTURE_TOOL   tcpdump or dumpcap (default: tcpdump if installed)
#   RESULTS_DIR    parent directory for all runs (default ./pqcbench-results)
#   OUTDIR         this run's directory (default $RESULTS_DIR/<timestamp>)
#   REMOTE_DIR     --remote: HOST's pqc-bench checkout, built with ./setup.sh
#                  (default pqc-bench, relative to the remote home; no spaces)
#   REMOTE_ADDR    --remote: the address clients connect to (default: HOST's
#                  HostName from `ssh -G`), resolved to IPv4 once
#   REMOTE_SSH     --remote: the ssh command (default ssh), e.g.
#                  "ssh -i ~/.ssh/my-key.pem"
#
# Exit status: 1 if any ML-DSA interop check or versions-mode case failed,
# otherwise 0.
#
# Requirements: a POSIX shell + awk/sed/sort/od, and one sub-millisecond clock
# source: GNU date (+%N), perl (Time::HiRes), or python3.
#
# wolfSSL build expected (setup.sh builds it this way; see README.md for what
# each option does):
#   ./configure --enable-mlkem --enable-mldsa --enable-curve25519 --enable-ed25519 \
#               --enable-tls13 --enable-tls-mlkem-standalone \
#               --enable-certgen --enable-certext --enable-keygen \
#               --enable-sp --enable-sp-asm --enable-armasm \
#               --disable-shared CPPFLAGS=-DWOLFSSL_ALT_NAMES
#   (on Intel/AMD use --enable-intelasm instead of --enable-armasm)
#   --enable-tls-mlkem-standalone: pure MLKEM512/768/1024 groups (without it
#     wolfSSL only offers ML-KEM inside hybrids).
#   --enable-certgen/--enable-certext: wolfSSL-issued ML-DSA certificates in
#     ML-DSA mode (without them those checks are skipped). WOLFSSL_ALT_NAMES
#     gives their leaves the OpenSSL-issued ones' subjectAltName (rustls needs it).
#   --enable-sp/--enable-sp-asm/--enable-armasm: optimized math and assembly;
#     without them EC, RSA and ML-KEM timings don't reflect a tuned wolfSSL.
#
# s2n-tls build expected: s2n-tls's CMake build against AWS-LC, with s2nc and
# s2nd in s2n-tls/build/bin (setup.sh builds it; see README.md). s2n-tls
# implements X25519, P-256, P-384, X25519MLKEM768, SecP256r1MLKEM768,
# SecP384r1MLKEM1024 and MLKEM1024 (no MLKEM512 or MLKEM768).
# `setup.sh --awslc-no-jitter` builds AWS-LC without CPU-jitter entropy (see
# NOTES ON THE NUMBERS); env.txt's `aws-lc entropy` line records which build ran.
#
# rustls build expected: rustls-tools/bin/pqc-rustls-<provider> (client, server,
# caps, speed) and hsloop/bin/hsloop-rustls-<provider>, built by `setup.sh
# rustls` (rustls 0.23, one build per crypto provider; see README.md).
# `pqc-rustls caps` says which groups, TLS versions and ML-DSA levels the
# provider has; pairs needing anything else are skipped with that reason.
#
# FIPS MODE (--fips)
#   Builds: `./setup.sh --fips` (next to the regular ones). OpenSSL runs with
#   OPENSSL_CONF=openssl-fips.cnf (the FIPS provider from OpenSSL 3.5.4 by
#   default, plus the base provider, default_properties fips=yes) and
#   OPENSSL_MODULES set, for every openssl command and hsloop-openssl. wolfSSL
#   is the FIPS Ready build (wolfCrypt FIPS v7: ML-KEM and ML-DSA, no
#   Curve25519). s2n-tls is linked to AWS-LC built with -DFIPS=1 and enters
#   FIPS mode in s2n_init. rustls runs aws-lc-rs's FIPS provider
#   (aws-lc-fips-sys) with its FIPS-approved groups. None of these is a
#   CMVP-validated module.
#   What changes: X25519 isn't tested (not FIPS-approved; dropped from the
#   groups and the --pure-pq fallbacks). X25519MLKEM768 stays: its ML-KEM part
#   is approved, and OpenSSL's provider and s2n-tls's FIPS policies offer it;
#   wolfSSL's FIPS build lacks it, so its pairs are skipped. The s2n-tls
#   tables switch to policies that pass s2n-tls's "FIPS 140-3 (2019)" rule
#   (see s2n_cli_policy). Versions mode is skipped. Start-up costs more: each
#   library checks its integrity and runs self-tests when it loads, AWS-LC
#   FIPS always seeds from CPU jitter, and wolfSSL (and AWS-LC on macOS) is
#   a shared library. env.txt records `fips: on` and each library's module.
#
# NETWORK SIMULATION (--mtu, --rtt, --bw)
#   Localhost hides two things a real path shows: flights cut into ~1.5 KB
#   segments, and round trips that cost time (a flight larger than TCP's
#   initial window of 10 segments waits a round trip for acknowledgements).
#   netsim.sh (next to this script) sets them up as root: sudo asks once, or
#   run as root (the Docker image is; pqcbench-docker.sh adds the NET_ADMIN
#   capability it needs). A watchdog restores everything when the run ends,
#   however it ends; `sudo ./netsim.sh down` restores by hand.
#     MTU: the loopback interface's (all its traffic, while the run lasts);
#       on Linux also gso_max_size, without which packets on lo stay up to
#       64 KB.
#     RTT and bandwidth: only TCP to and from BASE_PORT..BASE_PORT+999, half
#       the RTT each way (Linux: tc netem with u32 filters; macOS: dummynet
#       pipes with pf rules in the anchor com.apple/pqcbench). The start-up
#       baselines (no network, or a closed port below BASE_PORT) stay
#       unshaped, so adj_median_ms is handshake plus network. The RTT is
#       calibrated: netsim.sh scales the delay until a TCP connect takes it.
#     macOS also sets net.inet.tcp.local_slowstart_flightsize to 10 (local
#       connections otherwise start with 8 segments, not the usual 10).
#   env.txt's `netsim:` line records the settings and the measured RTT.
#   Times from such a run compare only with runs made with the same settings.
#
# REMOTE SERVERS (--remote HOST)
#   Handshakes over a real network path: the servers run on HOST, the clients
#   here. HOST needs the same pqc-bench checkout and builds (REMOTE_DIR, built
#   with ./setup.sh) and must accept TCP from this machine on
#   BASE_PORT..BASE_PORT+999: its servers listen on every interface, so allow
#   that range from this machine's address only (e.g. an AWS security group
#   rule with this machine's /32).
#   This script logs in once (REMOTE_SSH and your ssh config apply) and runs
#   `pqcbench.sh --serve` there: an agent that detects HOST's libraries, then
#   starts, checks and stops each server as the run goes. Certificates travel
#   over the same connection; when the run ends, however it ends, the agent
#   stops every server, and the server logs come back into logs/ (on a server
#   failure too). With --capture, the servers' TLS secrets come back as well,
#   and the capture runs here, on the interface towards HOST.
#   Clients connect to REMOTE_ADDR directly (no tunnel), so segment sizes,
#   round trips and congestion windows are the path's own. They check the
#   server certificate against the name localhost (s_client: the chain only),
#   never against the address, so the certificates stay as they are.
#   The RTT (the median of 15 request/reply exchanges with the agent over the
#   SSH connection; needs perl or python3 here) is measured at the start and
#   the end, into env.txt (`remote:`, `remote end:`), along with HOST's own
#   env.txt lines (`remote ...`). As with --rtt, the default
#   iterations drop to 20 / 10 / 5. The start-up baselines and the primitive
#   benchmarks still run here and measure this machine; `./pqcbench.sh
#   --primitives-only` on HOST measures its CPU. Not with --mtu/--rtt/--bw.
#
# NOTES ON THE NUMBERS
#   * Each handshake is timed as wall-clock for one client process: exec,
#     library init, TCP connect, full TLS 1.3 handshake, one small request/
#     response, close. A per-client startup baseline (measured with the same
#     clock, so it also absorbs the clock's own overhead) is subtracted in the
#     `adj_median_ms` column. Compare within one client implementation for
#     the cleanest signal. The s2n-tls baseline runs s2nc until a refused
#     connect, so it includes s2n_init. With stock AWS-LC that seeds its
#     CPU-jitter entropy source (~17 ms per process on an Apple M-series Mac).
#     That busy loop also slows s2nc's exec and exit by a further ~5 ms in a
#     varying share of runs, which the baseline can't remove.
#     An AWS-LC built with setup.sh --awslc-no-jitter seeds from the OS
#     instead and pays neither.
#     The rustls baseline runs pqc-rustls client until a refused connect, so
#     it includes setting up the provider; with aws-lc-rs that is seeding the
#     same CPU-jitter source (~20 ms), which runs slower after other
#     jitter-seeding processes (s2n-tls's clients), so its baseline can exceed
#     its handshakes. --awslc-no-jitter builds aws-lc-rs without it too.
#   * Timed runs follow each other back to back: a pause before a run (the
#     CPU clocks down) makes it slower. The wolfSSL example server exits after
#     a refused handshake, and so does s2nd in KEM and ML-DSA mode (it runs
#     without --parallelize there, which cost ~0.7 ms per handshake), so their
#     refusal checks are followed by a restart. In versions mode s2nd keeps
#     --parallelize, and wolfSSL's time-to-refusal samples follow a restart.
#   * Every run is a fresh process, so there is no session resumption.
#   * If a client's first key_share doesn't match what the server accepts,
#     you pay a HelloRetryRequest (an extra round trip). The OpenSSL client is
#     pinned with -groups, so it never triggers one. The wolfSSL client is
#     steered by the flags in the GROUP TABLE (libs/wolfssl.sh; verify them
#     with `client -?`), the s2n-tls client by the built-in policies in the
#     POLICY TABLE (libs/s2n.sh).
#
# LIBRARIES
#   Each library is a file in libs/ next to this script (see LIBRARY
#   INTERFACE below for what it implements); pqcbench.sh needs that directory.
# =============================================================================

# Variables set through eval (SPID_*, SPORT_*, SGRP_*, STARTUP_*, AV_*,
# KEM_TIMED_*, WOLF_HAS_*) are invisible to shellcheck, as are the
# t_*/mk_chain_* functions run indirectly by ml_check and gen_certs.
# shellcheck disable=SC2034,SC2154,SC2329

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
# --fips picks the FIPS builds, so look for it before the defaults
FIPS=0
for _a in "$@"; do [ "$_a" = --fips ] && FIPS=1; done
PQCB_DIR=$(dirname "$0")
# hsloop in-process clients (--inproc), built by setup.sh in hsloop/bin
: "${HSLOOP_DIR:=}"
if [ -z "$HSLOOP_DIR" ]; then
  for _cand in "$PQCB_DIR/hsloop/bin" ./hsloop/bin; do
    if [ -d "$_cand" ]; then HSLOOP_DIR=$_cand; break; fi
  done
fi

# ----------------------------------------------------------------------------
# LIBRARY INTERFACE
#   Every library under test is a file libs/<id>.sh next to this script,
#   listed in LIB_ALL (the order of the client x server matrix). It sets
#   LIBNAME_<id> (display name) and LIBREQ_<id> (1 = required; 0 = optional:
#   left out when not built, or with --no-<id>), optionally LIBSANONLY_<id>=1
#   (its client matches the server name against the subjectAltName only, never
#   the CN), and defines these functions (* = optional):
#     <id>_defaults            default binary paths (env overrides); FIPS is known
#     <id>_detect              absolute paths, FIPS checks; may set RUN_DIR (the
#                              directory runs start from). Optional libraries
#                              return 1 when not built, with LIBNOTE_<id> (and
#                              LIBNOTE_WARN_<id>=1 to warn) saying why
#     *<id>_prepare            after cd RUN_DIR: probes, working files under OUTDIR
#     <id>_label               "libraries:" entry; *<id>_info: extra Setup lines
#     <id>_env                 env.txt lines; *<id>_fips_env, *<id>_fips_desc (--fips)
#     <id>_speed kem|mldsa     primitive benchmarks (_what, _pd set by the caller)
#     <id>_cli_skip GROUP      why its client can't use GROUP (CERTK = chain), or nothing
#     <id>_srv_skip GROUP      why its server can't, or nothing
#     *<id>_has_group GROUP    0 if this build can use GROUP (build probe; call directly)
#     <id>_server GROUP PORT LOG KEYS  start the server in the background (SRV_CERT,
#                              SRV_KEY; SRV_CA = require client certificates),
#                              listening on SERVER_ADDR (127.0.0.1; 0.0.0.0 on
#                              a --remote HOST) or on every interface
#     *<id>_ready              after the port listens
#     *<id>_start_fail_hint GROUP LOG
#     <id>_client GROUP PORT [brief]   one client run against CONNECT_HOST (127.0.0.1,
#                              or --remote's HOST); prints the HTTP response
#                              (CLI_CA, CLI_CERT/CLI_KEY, CLI_KEYS)
#     *<id>_confirm LOG GROUP  preflight note: did the client negotiate GROUP?
#     *<id>_srv_pin_note       preflight note when its server pins the group
#     *<id>_preflight_why LOG GROUP, *<id>_why_hint GROUP WHY  preflight failures
#     <id>_startup             one process-startup baseline run;  *<id>_startup_note
#     <id>_inproc_bin          its hsloop client;  *<id>_inproc_exec GROUP CMD...
#     <id>_keylogs             0 if its programs write TLS secrets (--capture)
#     *<id>_cap_setup, *<id>_cleanup
#     *<id>_mldsa_hint, *<id>_mldsa_cli_skip GROUP   ML-DSA mode skip reasons
#     <id>_vs_server PORT LOG KEYS, <id>_vs_client PORT [brief]   versions mode
#     *<id>_vs_parse LOG       sets VS_VER, VS_RAWGRP, VS_HRRSEEN (default:
#                              OpenSSL-style output, vs_parse_default)
#     *<id>_vs_expect SCENARIO SERVER  adjust VS_EXPECT / VS_NOTE for its client
#     *<id>_vs_skip client|server  why it can't play the scenario's client or
#                              server as designed (a SKIP), or nothing
#     *<id>_option ARGS...     its own command-line options: sets OPT_SHIFT, or
#                              returns 1 when ARGS doesn't start with one
#     *<id>_instances          (after option parsing) set LIB_INSTANCES to the
#                              library ids it runs as, in place of <id> (e.g.
#                              rustls_ring rustls_graviola); each needs its own
#                              LIBNAME_/LIBREQ_ and these hooks
# ----------------------------------------------------------------------------
LIB_ALL="openssl wolfssl s2n rustls"
# does library IMPL define the optional hook OP?
lib_has() { command -v "$1_$2" >/dev/null 2>&1; }
lib_name() { eval "printf '%s\n' \"\$LIBNAME_$1\""; }
for _l in $LIB_ALL; do
  [ -f "$PQCB_DIR/libs/$_l.sh" ] || { printf 'x %s\n' "$PQCB_DIR/libs/$_l.sh not found (pqcbench.sh needs its libs/ directory)" >&2; exit 1; }
  # shellcheck disable=SC1090
  . "$PQCB_DIR/libs/$_l.sh"
  "${_l}_defaults"
done
# pqc-bench's own version: VERSION next to this script, plus the commit when
# it's a git checkout (results under examples/ don't count as changes)
_pv_d=$PQCB_DIR
PQCBENCH_VERSION=$(sed -n '1p' "$_pv_d/VERSION" 2>/dev/null)
if _pv_g=$(git -C "$_pv_d" rev-parse --short HEAD 2>/dev/null); then
  [ -z "$(git -C "$_pv_d" status --porcelain -- . ':(exclude)examples' 2>/dev/null)" ] \
    || _pv_g="$_pv_g, uncommitted changes"
else
  _pv_g=
fi
PQCBENCH_VERSION="${PQCBENCH_VERSION:-unknown}${_pv_g:+ (git $_pv_g)}"
# (set by the user: --rtt keeps them instead of lowering the defaults)
ITER_SET=${ITERATIONS:+1}; MLDSA_ITER_SET=${MLDSA_ITERATIONS:+1}; VS_ITER_SET=${VERSIONS_ITERATIONS:+1}
: "${ITERATIONS:=100}"
: "${MLDSA_ITERATIONS:=20}"
: "${WARMUP:=5}"
: "${SPEED_SECONDS:=3}"
: "${HS_TIMEOUT:=10}"
: "${BASE_PORT:=14433}"
[ -n "${CERT_ALG:-}" ] && { printf 'x %s\n' "CERT_ALG was replaced by --cert (e.g. --cert $CERT_ALG)" >&2; exit 2; }
KEM_CERTS=ec
CERT_ISSUER=openssl
: "${RESULTS_DIR:=./pqcbench-results}"
: "${OUTDIR:=$RESULTS_DIR/$(date +%Y%m%d-%H%M%S)}"
: "${MLDSA_KEY_FORMAT:=}"
: "${MLDSA_GROUP:=MLKEM768}"
: "${MLDSA_PROFILES:=44 65 87 87-44}"
: "${MLDSA_HELPER:=}"
: "${VERSIONS_ITERATIONS:=20}"
: "${CAPTURE_IFACE:=}"
: "${CAPTURE_TOOL:=}"
CAPTURE=0
NO_LIBS=
PURE_PQ=0
INPROC=0
# --remote HOST: servers there (REMOTE SERVERS); --serve RUN: this is HOST's agent
REMOTE=; SERVE=
: "${REMOTE_DIR:=pqc-bench}"
: "${REMOTE_ADDR:=}"
: "${REMOTE_SSH:=ssh}"
# where the clients connect and the servers listen (--remote: HOST, and
# every interface on HOST)
CONNECT_HOST=127.0.0.1; SERVER_ADDR=127.0.0.1

# ----------------------------------------------------------------------------
# GROUPS
#   GROUP_ORDER lists the key-exchange groups to test, by OpenSSL TLS group
#   name; each library maps them to its own flags (libs/<id>.sh; wolfSSL's
#   GROUP TABLE, s2n-tls's POLICY TABLE).
# ----------------------------------------------------------------------------
GROUP_ORDER="X25519 P-256 P-384
MLKEM512 MLKEM768 MLKEM1024
X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024"
GROUPS_KNOWN=$GROUP_ORDER
group_known() { case " $(echo $GROUPS_KNOWN) " in *" $1 "*) return 0 ;; esac; return 1; }

# key-exchange kind of a group name: pq (pure ML-KEM), hybrid or classical
group_kind() {
  case $1 in
    *MLKEM*) case $1 in X25519MLKEM*|SecP*) echo hybrid ;; *) echo pq ;; esac ;;
    '') echo "" ;;
    *) echo classical ;;
  esac
}

# --pure-pq: what a pair that can't use a pure ML-KEM group tries instead, in
# order: hybrids (same ML-KEM level first), then classical groups. --fips
# leaves out X25519 (not FIPS-approved).
pq_fallbacks() { # GROUP
  case $1 in
    MLKEM1024) _pf="SecP384r1MLKEM1024 X25519MLKEM768 SecP256r1MLKEM768 P-384 X25519 P-256" ;;
    *)         _pf="X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024 X25519 P-256 P-384" ;;
  esac
  if [ "$FIPS" = 1 ]; then _pf=$(printf '%s\n' "$_pf" | sed 's/ X25519 / /'); fi
  printf '%s\n' "$_pf"
}

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
if [ -t 1 ]; then
  C_B=$(printf '\033[1m'); C_CY=$(printf '\033[36m'); C_BL=$(printf '\033[34m')
  C_YL=$(printf '\033[33m'); C_RD=$(printf '\033[31m'); C_GR=$(printf '\033[32m')
  C_0=$(printf '\033[0m')
else
  C_B=; C_CY=; C_BL=; C_YL=; C_RD=; C_GR=; C_0=
fi
hdr()  { printf '\n%s%s== %s ==%s\n' "$C_B" "$C_CY" "$*" "$C_0"; }
sub()  { printf '\n%s%s%s\n' "$C_B" "$*" "$C_0"; }
info() { printf '%s*%s %s\n' "$C_BL" "$C_0" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YL" "$C_0" "$*" >&2; }
die()  { printf '%sx%s %s\n' "$C_RD" "$C_0" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '3,/^# =====*$/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

median_of() {
  sort -n | awk '{v[NR]=$1} END{ if(!NR){print 0; exit}
    if (NR%2) print v[(NR+1)/2]; else print (v[NR/2]+v[NR/2+1])/2 }'
}

# numbers on stdin -> "n,min,median,mean,p95,max,adj_median" (adj = median - $1)
stats_line() {
  sort -n | awk -v base="${1:-0}" '
    {v[NR]=$1; sum+=$1}
    END{
      if(!NR){print "0,,,,,,"; exit}
      n=NR; med=(n%2)?v[(n+1)/2]:(v[n/2]+v[n/2+1])/2
      p=0.95*n; i=int(p); if(i<p)i++; if(i<1)i=1
      printf "%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n", n, v[1], med, sum/n, v[i], v[n], med-base
    }'
}

# CSV on stdin -> aligned columns
print_table() {
  awk -F, '
    { for (i = 1; i <= NF; i++) { c[NR, i] = $i; if (length($i) > w[i]) w[i] = length($i) }
      if (NF > nf) nf = NF }
    END { for (r = 1; r <= NR; r++) { line = ""
            for (i = 1; i <= nf; i++) line = line sprintf("%-" w[i] "s  ", c[r, i])
            sub(/ +$/, "", line); print line } }'
}

# ----------------------------------------------------------------------------
# Args
# ----------------------------------------------------------------------------
DO_PRIM=1; DO_HS=1; DO_KEM=0; DO_MLDSA=0; DO_VERSIONS=0; VERSIONS_SCENARIOS=; GROUPS_SET=0
NS_MTU=; NS_RTT=; NS_BW=
while [ $# -gt 0 ]; do
  case $1 in
    -h|--help)          usage; exit 0 ;;
    --mlkem)            DO_KEM=1; shift ;;
    --mldsa)            DO_MLDSA=1; shift ;;
    --versions)         DO_VERSIONS=1; shift ;;
    --all)              DO_KEM=1; DO_MLDSA=1; DO_VERSIONS=1; shift ;;
    --versions-iterations) [ $# -ge 2 ] || die "$1 needs a value"; VERSIONS_ITERATIONS=$2; VS_ITER_SET=1; shift 2 ;;
    --versions-iterations=*) VERSIONS_ITERATIONS=${1#*=}; VS_ITER_SET=1; shift ;;
    --versions-scenarios) [ $# -ge 2 ] || die "$1 needs a value"; VERSIONS_SCENARIOS=$2; shift 2 ;;
    --versions-scenarios=*) VERSIONS_SCENARIOS=${1#*=}; shift ;;
    -n|--iterations)    [ $# -ge 2 ] || die "$1 needs a value"; ITERATIONS=$2; ITER_SET=1; shift 2 ;;
    --iterations=*)     ITERATIONS=${1#*=}; ITER_SET=1; shift ;;
    --mldsa-iterations) [ $# -ge 2 ] || die "$1 needs a value"; MLDSA_ITERATIONS=$2; MLDSA_ITER_SET=1; shift 2 ;;
    --mldsa-iterations=*) MLDSA_ITERATIONS=${1#*=}; MLDSA_ITER_SET=1; shift ;;
    --mtu)              [ $# -ge 2 ] || die "$1 needs a value"; NS_MTU=$2; shift 2 ;;
    --mtu=*)            NS_MTU=${1#*=}; shift ;;
    --rtt)              [ $# -ge 2 ] || die "$1 needs a value"; NS_RTT=$2; shift 2 ;;
    --rtt=*)            NS_RTT=${1#*=}; shift ;;
    --bw)               [ $# -ge 2 ] || die "$1 needs a value"; NS_BW=$2; shift 2 ;;
    --bw=*)             NS_BW=${1#*=}; shift ;;
    --groups)           [ $# -ge 2 ] || die "$1 needs a value"; GROUP_ORDER=$2; GROUPS_SET=1; shift 2 ;;
    --groups=*)         GROUP_ORDER=${1#*=}; GROUPS_SET=1; shift ;;
    --cert)             [ $# -ge 2 ] || die "$1 needs a value"; KEM_CERTS=$2; shift 2 ;;
    --cert=*)           KEM_CERTS=${1#*=}; shift ;;
    --cert-issuer)      [ $# -ge 2 ] || die "$1 needs a value"; CERT_ISSUER=$2; shift 2 ;;
    --cert-issuer=*)    CERT_ISSUER=${1#*=}; shift ;;
    --mldsa-profiles)   [ $# -ge 2 ] || die "$1 needs a value"; MLDSA_PROFILES=$2; shift 2 ;;
    --mldsa-profiles=*) MLDSA_PROFILES=${1#*=}; shift ;;
    --capture)          CAPTURE=1; shift ;;
    --primitives-only)  DO_HS=0; shift ;;
    --handshakes-only)  DO_PRIM=0; shift ;;
    --no-*)             _nl=${1#--no-}
                        case " $LIB_ALL " in *" $_nl "*) ;; *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;; esac
                        eval "_nr=\$LIBREQ_$_nl"
                        [ "$_nr" = 1 ] && die "$1: $(eval "echo \$LIBNAME_$_nl") is required"
                        NO_LIBS="$NO_LIBS $_nl"; shift ;;
    --inproc)           INPROC=1; shift ;;
    --pure-pq)          PURE_PQ=1; shift ;;
    --fips)             FIPS=1; shift ;;
    --remote)           [ $# -ge 2 ] || die "$1 needs a value"; REMOTE=$2; shift 2 ;;
    --remote=*)         REMOTE=${1#*=}; shift ;;
    --serve)            [ $# -ge 2 ] || die "$1 needs a value"; SERVE=$2; shift 2 ;;
    *)  # a library's own options (<id>_option ARGS... sets OPT_SHIFT)
        OPT_SHIFT=0
        for _l in $LIB_ALL; do
          lib_has "$_l" option && "${_l}_option" "$@" && break
        done
        [ "$OPT_SHIFT" -gt 0 ] || { printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2; }
        shift "$OPT_SHIFT" ;;
  esac
done
[ "$DO_KEM$DO_MLDSA$DO_VERSIONS" = 000 ] && DO_KEM=1
# --serve RUN: the agent a --remote run starts on its server host. It replies
# on fd 3 and reads requests from fd 4; everything else it prints goes to
# stderr, which ssh carries to the client's logs/remote-agent.log, and nothing
# it runs can read the requests.
if [ -n "$SERVE" ]; then
  [ -z "$REMOTE" ] || die "--serve and --remote don't combine"
  exec 3>&1 4<&0 1>&2 </dev/null
  OUTDIR=$RESULTS_DIR/$SERVE-servers
  SERVER_ADDR=0.0.0.0; DO_PRIM=0; DO_HS=1; INPROC=0; CAPTURE=0
fi
# --fips: versions mode is skipped (its scenarios are built on X25519 and
# X25519MLKEM768), and X25519 isn't tested (not FIPS-approved)
FIPS_SKIPPED_VERSIONS=0
if [ "$FIPS" = 1 ]; then
  if [ "$DO_VERSIONS" = 1 ]; then
    [ "$DO_KEM$DO_MLDSA" = 00 ] && die "--fips: versions mode isn't supported in FIPS mode (its scenarios are built on X25519)"
    DO_VERSIONS=0; FIPS_SKIPPED_VERSIONS=1
  fi
  _f_keep=; _f_drop=
  for _g in $GROUP_ORDER; do
    if [ "$_g" = X25519 ]; then _f_drop=X25519; else _f_keep="${_f_keep:+$_f_keep }$_g"; fi
  done
  GROUP_ORDER=$_f_keep
  [ "$GROUPS_SET" = 1 ] && [ -n "$_f_drop" ] && warn "--fips: X25519 isn't FIPS-approved; not testing it"
  [ -n "$GROUP_ORDER" ] || die "--fips: --groups has no FIPS-approved group"
  [ "$MLDSA_GROUP" = X25519 ] && [ "$DO_MLDSA" = 1 ] && die "--fips: MLDSA_GROUP=X25519 isn't FIPS-approved"
fi
# --remote: a real path, where every sample costs round trips, as with --rtt
if [ -n "$REMOTE" ]; then
  [ -z "$NS_MTU$NS_RTT$NS_BW" ] || die "--remote measures a real network path: not with --mtu/--rtt/--bw"
  [ -n "$ITER_SET" ] || ITERATIONS=20
  [ -n "$MLDSA_ITER_SET" ] || MLDSA_ITERATIONS=10
  [ -n "$VS_ITER_SET" ] || VERSIONS_ITERATIONS=5
fi
# network simulation (netsim.sh): --rtt / --bw imply a 1500-byte MTU; a
# delayed path makes every sample cost round trips, so fewer by default
NETSIM=0; NS_SETTLE=
if [ -n "$NS_MTU$NS_RTT$NS_BW" ]; then
  NETSIM=1
  : "${NS_MTU:=1500}"
  case $NS_MTU in ''|*[!0-9]*) die "--mtu needs a number" ;; esac
  case $NS_RTT in ''|*[!0-9.]*|*.*.*) [ -z "$NS_RTT" ] || die "--rtt needs a number of milliseconds" ;; esac
  case $NS_BW in ''|[0-9]*kbit|[0-9]*mbit|[0-9]*gbit) ;; *) die "--bw: a number with kbit, mbit or gbit (e.g. 10mbit)" ;; esac
  [ -f "$PQCB_DIR/netsim.sh" ] || die "--mtu/--rtt/--bw need netsim.sh next to this script"
  # absolute: sudo may start it in another directory
  NETSIM_SH=$(cd "$PQCB_DIR" && pwd)/netsim.sh
  if [ -n "$NS_RTT" ] && awk -v r="$NS_RTT" 'BEGIN { exit !(r > 0) }'; then
    [ -n "$ITER_SET" ] || ITERATIONS=20
    [ -n "$MLDSA_ITER_SET" ] || MLDSA_ITERATIONS=10
    [ -n "$VS_ITER_SET" ] || VERSIONS_ITERATIONS=5
    # a handshake with a HelloRetryRequest and a large ML-DSA flight is ~6
    # round trips; keep the per-handshake timeout well above that
    _ns_to=$(awk -v r="$NS_RTT" 'BEGIN { printf "%d", r * 50 / 1000 + 1 }')
    if [ "$HS_TIMEOUT" -lt "$_ns_to" ]; then
      warn "--rtt $NS_RTT: HS_TIMEOUT raised from $HS_TIMEOUT to $_ns_to s"
      HS_TIMEOUT=$_ns_to
    fi
    # a server learns of a client's refusal half a round trip after the client
    # exits: ensure_server/vs_ensure wait this long (seconds) before checking it
    NS_SETTLE=$(awk -v r="$NS_RTT" 'BEGIN { printf "%.3f", r / 1000 }')
  fi
fi
case $ITERATIONS       in ''|*[!0-9]*) die "iterations must be a positive integer" ;; esac
case $MLDSA_ITERATIONS in ''|*[!0-9]*) die "mldsa iterations must be a non-negative integer" ;; esac
case $VERSIONS_ITERATIONS in ''|*[!0-9]*) die "versions iterations must be a non-negative integer" ;; esac
case $WARMUP           in ''|*[!0-9]*) die "WARMUP must be a non-negative integer" ;; esac

# profile "87-44" -> ML_CAL=87 ML_LL=44 ; "65" -> 65 65
ml_split() {
  case $1 in
    *-*) ML_CAL=${1%%-*}; ML_LL=${1#*-} ;;
    *)   ML_CAL=$1; ML_LL=$1 ;;
  esac
  case $ML_CAL in 44|65|87) ;; *) return 1 ;; esac
  case $ML_LL  in 44|65|87) ;; *) return 1 ;; esac
}
if [ "$DO_MLDSA" = 1 ]; then
  for _p in $MLDSA_PROFILES; do
    ml_split "$_p" || die "bad ML-DSA profile '$_p' (use 44, 65, 87 or CA-LEAF such as 87-44)"
  done
fi
# --cert: KEM mode server certificates, ec or mldsa<profile> (the profiles of
# ML-DSA mode: mldsa65, mldsa87-44); duplicates dropped, order kept
_kc=
for _c in $KEM_CERTS; do
  [ "$_c" = all ] && _c="ec mldsa44 mldsa65 mldsa87 mldsa87-44"
  for _c in $_c; do
    case $_c in
      ec) ;;
      mldsa*) ml_split "${_c#mldsa}" ||
                die "--cert: bad certificate '$_c' (ec, mldsa44, mldsa65, mldsa87, or mldsa<CA>-<leaf> such as mldsa87-44)"
              if [ "$ML_CAL" = "$ML_LL" ]; then _c=mldsa$ML_CAL; else _c=mldsa$ML_CAL-$ML_LL; fi ;;
      *) die "--cert: unknown certificate '$_c' (ec, mldsa44, mldsa65, mldsa87, mldsa<CA>-<leaf> or all)" ;;
    esac
    case " $_kc " in *" $_c "*) ;; *) _kc="${_kc:+$_kc }$_c" ;; esac
  done
done
[ -n "$_kc" ] || die "--cert needs at least one certificate"
KEM_CERTS=$_kc
case $CERT_ISSUER in openssl|wolfssl) ;; *) die "--cert-issuer: openssl or wolfssl" ;; esac

# --pure-pq: KEM mode tests only the pure ML-KEM groups; ML-DSA mode needs one
if [ "$PURE_PQ" = 1 ]; then
  _pq_keep=; _pq_drop=
  for _g in $GROUP_ORDER; do
    if [ "$(group_kind "$_g")" = pq ]; then _pq_keep="${_pq_keep:+$_pq_keep }$_g"
    else _pq_drop="${_pq_drop:+$_pq_drop }$_g"; fi
  done
  GROUP_ORDER=$_pq_keep
  if [ "$DO_KEM" = 1 ] && [ "$DO_HS" = 1 ]; then
    [ -n "$GROUP_ORDER" ] || die "--pure-pq: --groups has no pure ML-KEM group (MLKEM512, MLKEM768, MLKEM1024)"
    [ "$GROUPS_SET" = 1 ] && [ -n "$_pq_drop" ] && warn "--pure-pq: not testing groups that aren't pure ML-KEM: $_pq_drop"
  fi
  if [ "$DO_MLDSA" = 1 ] && [ "$DO_HS" = 1 ] && [ "$(group_kind "$MLDSA_GROUP")" != pq ]; then
    die "--pure-pq: MLDSA_GROUP=$MLDSA_GROUP isn't a pure ML-KEM group (MLKEM512, MLKEM768, MLKEM1024)"
  fi
fi

# ----------------------------------------------------------------------------
# Clock (nanoseconds since epoch, integer)
# ----------------------------------------------------------------------------
CLOCK=
_d=$(date +%s%N 2>/dev/null)
# a nanosecond count has 19 digits; busybox date prints %N as nothing, which
# leaves whole seconds that would pass for nanoseconds
case $_d in
  ''|*[!0-9]*) ;;
  *) [ ${#_d} -ge 19 ] && CLOCK='date' ;;
esac
if [ -z "$CLOCK" ] && have perl && perl -MTime::HiRes -e1 2>/dev/null; then CLOCK=perl; fi
if [ -z "$CLOCK" ] && have python3; then CLOCK=python3; fi
[ -n "$CLOCK" ] || die "need GNU date (+%N), perl or python3 for sub-millisecond timing"

now_ns() {
  case $CLOCK in
    date)    date +%s%N ;;
    perl)    perl -MTime::HiRes=time -e 'printf "%.0f\n", time()*1e9' ;;
    python3) python3 -c 'import time; print(time.time_ns())' ;;
  esac
}
# elapsed_ms T0_NS T1_NS -> "12.345"
elapsed_ms() {
  _us=$(( ($2 - $1) / 1000 ))
  printf '%d.%03d\n' $(( _us / 1000 )) $(( _us % 1000 ))
}

# ----------------------------------------------------------------------------
# Misc helpers
# ----------------------------------------------------------------------------
TO_CMD=
if   have timeout;  then TO_CMD="timeout $HS_TIMEOUT"
elif have gtimeout; then TO_CMD="gtimeout $HS_TIMEOUT"
else warn "no timeout/gtimeout found; a hung handshake will stall the run (macOS: brew install coreutils)"
fi

if   have ss;      then PORT_TOOL=ss
elif have lsof;    then PORT_TOOL=lsof
elif have netstat; then PORT_TOOL=netstat
else PORT_TOOL=none
fi
port_listening() {
  case $PORT_TOOL in
    ss)      ss -ltn 2>/dev/null | awk -v p="$1" '$4 ~ ("[:.]" p "$") {f=1} END{exit !f}' ;;
    lsof)    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1 ;;
    netstat) netstat -an 2>/dev/null | grep LISTEN | grep -q "[.:]$1 " ;;
    none)    return 0 ;;
  esac
}
wait_listen() {
  if [ "$PORT_TOOL" = none ]; then sleep 1; return 0; fi
  _wl=0
  while [ $_wl -lt 100 ]; do
    port_listening "$1" && return 0
    sleep 0.05 2>/dev/null || sleep 1
    _wl=$((_wl + 1))
  done
  return 1
}

# ----------------------------------------------------------------------------
# Preconditions: the libraries under test (LIBS)
# ----------------------------------------------------------------------------
abspath() { # PATH -> absolute (for paths containing a slash)
  case $1 in
    /*)  printf '%s\n' "$1" ;;
    */*) printf '%s/%s\n' "$(cd "$(dirname "$1")" 2>/dev/null && pwd)" "$(basename "$1")" ;;
    *)   printf '%s\n' "$1" ;;
  esac
}
[ -n "$MLDSA_HELPER" ] && MLDSA_HELPER=$(abspath "$MLDSA_HELPER")
# (lib_has and lib_name are defined with LIB_ALL, under LIBRARY INTERFACE)

# libraries that run as several (rustls with several crypto providers) take
# their place in LIB_ALL now that the options are known (<id>_instances)
_la=
for _l in $LIB_ALL; do
  case " $NO_LIBS " in *" $_l "*) _la="$_la $_l"; continue ;; esac
  if lib_has "$_l" instances; then "${_l}_instances"; _la="$_la $LIB_INSTANCES"; else _la="$_la $_l"; fi
done
LIB_ALL=${_la# }

# every library's paths are made absolute before the run moves to RUN_DIR
RUN_DIR=; LIBS=; LIBS_OUT=
for _l in $LIB_ALL; do
  case " $NO_LIBS " in *" $_l "*) continue ;; esac
  if "${_l}_detect"; then
    LIBS="${LIBS:+$LIBS }$_l"
  else
    eval "_lr=\$LIBREQ_$_l"
    [ "$_lr" = 1 ] && die "$(lib_name "$_l") is required but wasn't found"
    LIBS_OUT="${LIBS_OUT:+$LIBS_OUT }$_l"
  fi
done
# width of the library columns in the progress lines (longer ids: rustls_<provider>)
LIBW=8
for _l in $LIBS; do [ ${#_l} -gt $LIBW ] && LIBW=${#_l}; done
LIBW2=$((LIBW * 2 + 2)); [ $LIBW2 -lt 16 ] && LIBW2=16

# Results dir (absolute), since we change directory below.
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"
OUTDIR=$(cd "$OUTDIR" && pwd)
LOGDIR=$OUTDIR/logs; CERTDIR=$OUTDIR/certs
mkdir -p "$LOGDIR" "$CERTDIR"
RAW=; SUMMARY=; MLCSV=; MLSUM=; VSCSV=; VSSUM=; INSUM=; MLINSUM=
if [ -n "$RUN_DIR" ]; then cd "$RUN_DIR" || die "cannot cd to $RUN_DIR"; fi
for _l in $LIBS; do lib_has "$_l" prepare && "${_l}_prepare"; done

# --inproc: the hsloop client of each library under test (INPROC_LIBS)
INPROC_LIBS=; INPROC_NOTE=
if [ "$INPROC" = 1 ]; then
  for _il in $LIBS; do
    _ib=$("${_il}_inproc_bin")
    if [ -n "$_ib" ] && [ -x "$_ib" ]; then
      INPROC_LIBS="${INPROC_LIBS:+$INPROC_LIBS }$_il"
    else
      INPROC_NOTE="${INPROC_NOTE:+$INPROC_NOTE; }hsloop-$_il not found${_ib:+ ($_ib)}"
    fi
  done
  if [ -z "$INPROC_LIBS" ]; then
    warn "--inproc: no hsloop clients found ($INPROC_NOTE); build them with ./setup.sh hsloop. In-process timing skipped."
    INPROC=0
  fi
fi

_modes=
[ "$DO_KEM" = 1 ] && _modes="kem"
[ "$DO_MLDSA" = 1 ] && _modes="${_modes:+$_modes+}mldsa"
[ "$DO_VERSIONS" = 1 ] && _modes="${_modes:+$_modes+}versions"
# this host and its builds: the start of env.txt, and all of a --serve agent's
# (which a --remote run copies into its own as "remote ..." lines)
host_env() {
  echo "date: $(date)"
  echo "pqc-bench version: $PQCBENCH_VERSION"
  echo "host: $(uname -a)"
  for _l in $LIBS; do "${_l}_env"; done
  echo "libraries: $LIBS"
  if [ "$FIPS" = 1 ]; then
    echo "fips: on"
    for _l in $LIBS; do lib_has "$_l" fips_env && "${_l}_fips_env"; done
  else
    echo "fips: off"
  fi
}
host_env > "$OUTDIR/env.txt"
[ -n "$SERVE" ] || {
  echo "modes: $_modes  primitives=$DO_PRIM handshakes=$DO_HS"
  echo "iterations=$ITERATIONS mldsa_iterations=$MLDSA_ITERATIONS warmup=$WARMUP clock=$CLOCK"
  printf 'groups: %s\n' "$(echo "$GROUP_ORDER" | tr '\n' ' ')"
  echo "certs: $KEM_CERTS"
  echo "cert issuer: $CERT_ISSUER"
  if [ "$PURE_PQ" = 1 ]; then echo "pure-pq: on"; else echo "pure-pq: off"; fi
  echo "mldsa profiles: $MLDSA_PROFILES  group: $MLDSA_GROUP"
  echo "versions iterations: $VERSIONS_ITERATIONS  scenarios: ${VERSIONS_SCENARIOS:-all}"
  if [ "$INPROC" = 1 ]; then
    _ie=
    for _il in $INPROC_LIBS; do _ie="${_ie:+$_ie, }$("${_il}_inproc_bin")"; done
    echo "inproc: on ($_ie)${INPROC_NOTE:+; $INPROC_NOTE}"
  else
    echo "inproc: off"
  fi
  [ "$FIPS_SKIPPED_VERSIONS" = 1 ] && echo "fips versions mode: skipped"
  # (with --mtu/--rtt/--bw, netsim_up appends the settings it applied;
  # with --remote, remote_up its own)
  [ "$NETSIM" = 1 ] || echo "netsim: off"
} >> "$OUTDIR/env.txt"

hdr "Setup"
info "results -> $OUTDIR"
info "pqc-bench $PQCBENCH_VERSION"
info "$OSSL_VER"
info "mode: $_modes"
info "clock source: $CLOCK"
_ll=
for _l in $LIBS; do _ll="${_ll:+$_ll, }$("${_l}_label")"; done
info "libraries: $_ll"
for _l in $LIBS; do lib_has "$_l" info && "${_l}_info"; done
for _l in $LIBS_OUT; do
  eval "_ln=\${LIBNOTE_$_l:-}; _lw=\${LIBNOTE_WARN_$_l:-0}"
  if [ "$_lw" = 1 ]; then warn "$_ln"; elif [ -n "$_ln" ]; then info "$_ln"; fi
done
if [ "$PURE_PQ" = 1 ]; then
  info "pure PQ: pure ML-KEM key exchange wherever a pair supports it; fallbacks to hybrid, then classical, are noted"
fi
if [ "$FIPS" = 1 ]; then
  _fd=
  for _l in $LIBS; do lib_has "$_l" fips_desc && _fd="${_fd:+$_fd; }$("${_l}_fips_desc")"; done
  info "FIPS mode: $_fd"
  info "  groups: $(echo "$GROUP_ORDER" | tr '\n' ' ')(no X25519); FIPS-approved choices in every library"
  [ "$FIPS_SKIPPED_VERSIONS" = 1 ] && warn "--fips: versions mode skipped (its scenarios are built on X25519)"
fi
if [ "$INPROC" = 1 ]; then
  info "in-process timing (--inproc): hsloop clients for $INPROC_LIBS"
  [ -n "$INPROC_NOTE" ] && warn "  $INPROC_NOTE (those clients' pairs get no in-process timing)"
fi

# ----------------------------------------------------------------------------
# Primitive benchmarks
# ----------------------------------------------------------------------------
run_primitives() { # kem|mldsa
  _pd=$OUTDIR/primitives; mkdir -p "$_pd"
  if [ "$1" = kem ]; then _what="key exchange"; else _what="signatures"; fi
  for _rp_l in $LIBS; do "${_rp_l}_speed" "$1"; done
  return 0
}

# ----------------------------------------------------------------------------
# TLS servers and clients (shared by both modes)
#   Servers use SRV_CERT / SRV_KEY, and require + verify client certs against
#   SRV_CA when it is set. Clients verify the server against CLI_CA and present
#   CLI_CERT / CLI_KEY when CLI_CERT is set.
# ----------------------------------------------------------------------------
SRV_CERT=; SRV_KEY=; SRV_CA=; CLI_CA=; CLI_CERT=; CLI_KEY=
# per library: server PID and port, the group its server runs with, the label
# its server last failed to start for, its process-startup baseline
for _l in $LIB_ALL; do eval "SPID_$_l=; SPORT_$_l=; SGRP_$_l=; START_FAILED_$_l=; STARTUP_$_l=0"; done
NEXT_PORT=$BASE_PORT
# KEM mode server certificate in use (also picks the s2n client's policy): ec,
# mldsa<level>, or mldsa<CA>-<leaf> for a mixed-level ML-DSA chain (see
# s2n_cli_policy); ML-DSA mode sets it per chain profile
CERTK=ec
# CERTK as text: "ECDSA P-256", "ML-DSA-87", "ML-DSA-87/ML-DSA-44"
certk_desc() {
  case $CERTK in
    mldsa*-*) _cd=${CERTK#mldsa}; echo "ML-DSA-${_cd%-*}/ML-DSA-${_cd#*-}" ;;
    mldsa*)   echo "ML-DSA-${CERTK#mldsa}" ;;
    ec)       echo "ECDSA P-256" ;;
    *)        echo "$CERTK" ;;
  esac
}

start_server() { # IMPL GROUP [LABEL]
  _ss_impl=$1; _ss_group=$2; _ss_label=${3:-$2}
  eval "_ss_port=\$SPORT_$_ss_impl"
  _ss_log=$LOGDIR/server-$_ss_impl-$_ss_label.log
  if [ -n "$REMOTE" ]; then
    remote_put "$SRV_CERT"; remote_put "$SRV_KEY"; remote_put "$SRV_CA"
    remote_rel "$SRV_CERT"; _ss_c=$RREL; remote_rel "$SRV_KEY"; _ss_k=$RREL; remote_rel "$SRV_CA"
    remote_server "$_ss_impl" "$_ss_group" "$_ss_label" \
      "start $_ss_impl $_ss_group $_ss_label $_ss_port ${CERTK:--} $CAPTURE $_ss_c $_ss_k $RREL"
    return
  fi
  "${_ss_impl}_server" "$_ss_group" "$_ss_port" "$_ss_log" "$(srv_keys "$_ss_impl" "$_ss_label")"
  eval "SPID_$_ss_impl=\$!; SGRP_$_ss_impl=\$_ss_group"
  if ! wait_listen "$_ss_port"; then
    eval "START_FAILED_$_ss_impl=\$_ss_label"
    warn "$_ss_impl server didn't start for $_ss_label (see $_ss_log)"
    lib_has "$_ss_impl" start_fail_hint && "${_ss_impl}_start_fail_hint" "$_ss_group" "$_ss_log"
    return 1
  fi
  if lib_has "$_ss_impl" ready; then "${_ss_impl}_ready"; fi
  return 0
}

stop_server() { # IMPL
  eval "_st_pid=\$SPID_$1"
  if [ -n "$_st_pid" ]; then
    if [ -n "$REMOTE" ]; then
      remote_req "stop $1"
    else
      kill "$_st_pid" 2>/dev/null
      wait "$_st_pid" 2>/dev/null
    fi
  fi
  eval "SPID_$1=; SGRP_$1="
}
stop_servers() { for _sx in $LIBS; do stop_server "$_sx"; done; }

# --mtu/--rtt/--bw: netsim.sh as root (sudo, once, unless this is root), with
# a watchdog that restores the network settings when this script exits
NETSIM_ON=0
netsim_up() {
  [ "$NETSIM" = 1 ] || return 0
  hdr "Network simulation"
  if [ "$(id -u)" = 0 ]; then
    _nu_sudo=
  else
    command -v sudo >/dev/null 2>&1 || die "--mtu/--rtt/--bw need root, and there's no sudo"
    if ! sudo -n true 2>/dev/null; then
      [ -t 0 ] || die "--mtu/--rtt/--bw need root: run as root, or where sudo can ask for a password"
      info "netsim.sh changes the loopback interface and needs root: sudo asks for your password once"
      info "  (a watchdog restores the settings when this run ends, however it ends)"
    fi
    _nu_sudo=sudo
  fi
  set -- up --mtu "$NS_MTU" --ports "$BASE_PORT-$((BASE_PORT + 999))" --watch "$$"
  [ -n "$NS_RTT" ] && set -- "$@" --rtt "$NS_RTT"
  [ -n "$NS_BW" ] && set -- "$@" --bw "$NS_BW"
  NETSIM_LINE=$($_nu_sudo sh "$NETSIM_SH" "$@") || die "network simulation failed (see above)"
  NETSIM_ON=1
  echo "netsim: $NETSIM_LINE" >> "$OUTDIR/env.txt"
  info "network: $NETSIM_LINE"
  if [ -n "$NS_RTT" ]; then
    info "  every sample costs several round trips: iterations $ITERATIONS / $MLDSA_ITERATIONS / $VERSIONS_ITERATIONS (key exchange / ML-DSA / versions)"
  fi
}
netsim_down() {
  [ "$NETSIM_ON" = 1 ] || return 0
  NETSIM_ON=0
  # the RTT again (no root needed): env.txt shows any drift during the run
  if [ -n "$NS_SETTLE" ] && _nd_ms=$(sh "$NETSIM_SH" probe "$((BASE_PORT + 999))" 2>/dev/null); then
    echo "netsim end: measured $_nd_ms ms" >> "$OUTDIR/env.txt"
  fi
  if [ "$(id -u)" = 0 ]; then
    sh "$NETSIM_SH" down
  elif ! sudo -n sh "$NETSIM_SH" down 2>/dev/null; then
    info "network settings: netsim.sh's watchdog restores them within a second"
  fi
}

# ----------------------------------------------------------------------------
# --remote: the servers on another host
#   The client (--remote HOST) starts `pqcbench.sh --serve RUN` on HOST over
#   one SSH connection (FIFOs on fds 7 and 8 here) and keeps it for the run:
#   an agent that detects HOST's libraries once, then runs start_server,
#   vs_start_server and stop_server there on request, one line each way:
#     sync TOKEN                          -> TOKEN
#     put REL N, then N lines of base64   -> ok | fail WHY   (a file of the run)
#     get REL                             -> data N, then N lines of base64 | none
#     logs                                -> as get, a tar of logs/server-*.log
#     start IMPL GROUP LABEL PORT CERTK KEYS CERT KEY CA  -> ok PID | fail [WHY]
#     vstart IMPL LABEL PORT KEYS SV SG CERT KEY          -> ok PID | fail [WHY]
#     alive IMPL PORT                     -> yes | no
#     stop IMPL                           -> ok
#     quit                                -> bye, once every server is stopped
#   REL, CERT, KEY and CA are paths relative to the run directory (- for
#   none; on HOST it is pqcbench-results/RUN-servers); KEYS 1 logs the
#   server's TLS secrets (--capture); CERTK, SV and SG set CERTK, VS_SV and
#   VS_SG. The agent first sends its env.txt ("env LINE" each), then
#   "ready PROTO LIBS...".
# ----------------------------------------------------------------------------
REMOTE_PROTO=1
REMOTE_UP=0; REMOTE_PID=; REMOTE_LOG=; REMOTE_SENT=; RREPLY=; RREL=
REMOTE_RTT_HOW="request/reply with the agent over the SSH connection, median of 15"

# NAME -> its IPv4 address (an address as it is), or nothing
ipv4_of() {
  case $1 in *[!0-9.]*) ;; *) printf '%s\n' "$1"; return 0 ;; esac
  if have perl; then
    perl -MSocket -e '$a = gethostbyname($ARGV[0]) or exit 1; print inet_ntoa($a), "\n"' "$1"
  elif have python3; then
    python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$1" 2>/dev/null
  fi
}
# the round trip (ms) over the agent's connection: 15 sync requests timed in
# one process (perl or python3) that shares fds 7 and 8, or nothing. (Not TCP
# connects to the SSH port: sshd penalises connections that don't log in.)
# Follow it with remote_sync: a probe that failed may leave a reply behind.
remote_rtt() {
  if have perl; then
    perl -MTime::HiRes=time -e '
      open(my $w, ">&=", 7) or exit 1; open(my $r, "<&=", 8) or exit 1;
      select((select($w), $| = 1)[0]);
      my @t;
      for my $i (1 .. 15) {
        my $t0 = time; print $w "sync rtt$i\n";
        my $l = <$r>; defined $l && $l eq "rtt$i\n" or exit 1;
        push @t, (time - $t0) * 1000;
      }
      @t = sort { $a <=> $b } @t; printf "%.2f\n", $t[7];'
  elif have python3; then
    python3 -c '
import os, time
w, r = os.fdopen(7, "w", buffering=1), os.fdopen(8, "r")
t = []
for i in range(1, 16):
    t0 = time.perf_counter()
    w.write("sync rtt%d\n" % i)
    if r.readline() != "rtt%d\n" % i:
        raise SystemExit(1)
    t.append((time.perf_counter() - t0) * 1000)
print("%.2f" % sorted(t)[7])' 2>/dev/null
  fi
}

# the agent's last log lines, for an error message
remote_log_tail() { [ -s "$REMOTE_LOG" ] && printf '\n%s' "$(tail -n 5 "$REMOTE_LOG" | sed 's/^/    /')"; }
remote_lost() {
  REMOTE_UP=0
  # (once ssh has exited, its log is complete)
  wait "$REMOTE_PID" 2>/dev/null
  die "--remote: lost the connection to $REMOTE's agent (logs/$(basename "$REMOTE_LOG")):$(remote_log_tail)"
}
# one request line (or several) to the agent; RREPLY: its next reply line.
# Both end the run when the connection is gone.
remote_send() {
  [ "$REMOTE_UP" = 1 ] || return 1
  # (a subshell that ignores SIGPIPE: a closed connection fails the write
  # instead of killing this script. Its whole stdout is fd 7: bash's printf
  # would otherwise flush what it failed to write to the terminal on exit.)
  ( trap '' PIPE; printf '%s\n' "$*" ) >&7 2>/dev/null || remote_lost
}
remote_recv() {
  [ "$REMOTE_UP" = 1 ] || return 1
  IFS= read -r RREPLY <&8 || remote_lost
}
remote_req() { remote_send "$@" && remote_recv; }

# skip the agent's replies up to TOKEN's (after an interrupt or a failed
# remote_rtt, a reply may still be on its way)
remote_sync() { # TOKEN
  remote_send "sync $1" || return 1
  while remote_recv; do [ "$RREPLY" = "$1" ] && return 0; done
  return 1
}

# PATH (under OUTDIR) -> RREL: the same file in the agent's run directory, - for none
remote_rel() {
  case $1 in
    '') RREL=- ;;
    "$OUTDIR"/*) RREL=${1#"$OUTDIR"/} ;;
    *) die "--remote: $1 isn't in the run directory, so the servers can't have it" ;;
  esac
}
# FILE (under OUTDIR; nothing for '') -> the agent, once per run
remote_put() {
  [ -n "$1" ] || return 0
  remote_rel "$1"
  case " $REMOTE_SENT " in *" $RREL "*) return 0 ;; esac
  _rmp_b=$("$OPENSSL" base64 -e -in "$1") || die "--remote: can't read $1"
  _rmp_n=0; [ -n "$_rmp_b" ] && _rmp_n=$(printf '%s\n' "$_rmp_b" | wc -l | tr -d ' ')
  remote_send "put $RREL $_rmp_n${_rmp_b:+
$_rmp_b}"
  remote_recv
  [ "$RREPLY" = ok ] || die "--remote: sending $RREL to $REMOTE failed: $RREPLY"
  REMOTE_SENT="$REMOTE_SENT $RREL"
}
# the reply to REQUEST, "data N" and N lines of base64, decoded into FILE;
# 1 when the agent sends none
remote_fetch() { # REQUEST FILE
  remote_req "$1" || return 1
  case $RREPLY in "data "*) ;; *) return 1 ;; esac
  _rmf_n=${RREPLY#data }; _rmf_i=0
  mkdir -p "$(dirname "$2")"
  while [ "$_rmf_i" -lt "$_rmf_n" ]; do
    remote_recv || return 1
    printf '%s\n' "$RREPLY"
    _rmf_i=$((_rmf_i + 1))
  done > "$2.b64"
  "$OPENSSL" base64 -d -in "$2.b64" -out "$2"; _rmf_rc=$?
  rm -f "$2.b64"
  return $_rmf_rc
}
# FILE (under OUTDIR) <- the agent's copy, if it has one
remote_get() { remote_rel "$1"; remote_fetch "get $RREL" "$1"; }

# start IMPL's server on HOST with REQUEST (start or vstart), as start_server
# does here: SPID_ (the agent's PID) and SGRP_ (GROUP), or on failure
# START_FAILED_, a warning, and the server's log fetched into logs/
remote_server() { # IMPL GROUP LABEL REQUEST
  remote_req "$4" || return 1
  case $RREPLY in
    "ok "*) eval "SPID_$1=\${RREPLY#ok }; SGRP_$1=\$2"; return 0 ;;
  esac
  _rms_why=${RREPLY#fail}; _rms_why=${_rms_why# }
  eval "SPID_$1=; SGRP_$1=\$2; START_FAILED_$1=\$3"
  _rms_log=$LOGDIR/server-$1-$3.log
  _rms_see=; remote_get "$_rms_log" && _rms_see=" (see $_rms_log)"
  warn "$1 server on $REMOTE didn't start for $3${_rms_why:+: $_rms_why}$_rms_see"
  [ -n "$2" ] && lib_has "$1" start_fail_hint && "${1}_start_fail_hint" "$2" "$_rms_log"
  return 1
}
remote_alive() { remote_req "alive $1 $2" && [ "$RREPLY" = yes ]; } # IMPL PORT

# connect to HOST and start its agent (Main, before anything is timed)
remote_up() {
  [ -n "$REMOTE" ] || return 0
  if [ "$DO_HS" != 1 ]; then warn "--remote has nothing to do with --primitives-only"; return 0; fi
  hdr "Remote servers"
  # the address the clients connect to: HOST's HostName (ssh config), as IPv4,
  # so that no client looks up a name inside a timed handshake
  # shellcheck disable=SC2086
  _rmu_cfg=$($REMOTE_SSH -G "$REMOTE" 2>/dev/null)
  _rmu_a=${REMOTE_ADDR:-$(printf '%s\n' "$_rmu_cfg" | awk '$1 == "hostname" { print $2; exit }')}
  [ -n "$_rmu_a" ] || _rmu_a=${REMOTE#*@}
  CONNECT_HOST=$(ipv4_of "$_rmu_a")
  [ -n "$CONNECT_HOST" ] ||
    die "--remote: can't resolve $_rmu_a to an IPv4 address (that needs perl or python3); set REMOTE_ADDR to one"

  _rmu_d=$OUTDIR/tools/remote; mkdir -p "$_rmu_d"; rm -f "$_rmu_d/in" "$_rmu_d/out"
  mkfifo "$_rmu_d/in" "$_rmu_d/out" || die "mkfifo failed (--remote talks to HOST's agent through FIFOs)"
  REMOTE_LOG=$LOGDIR/remote-agent.log
  # the agent's options: those that decide which libraries it runs
  set -- --serve "$(basename "$OUTDIR" | tr -c 'A-Za-z0-9._\n-' _)"
  [ "$FIPS" = 1 ] && set -- "$@" --fips
  for _rmu_l in $NO_LIBS; do set -- "$@" "--no-$_rmu_l"; done
  case " $NO_LIBS " in
    *" rustls "*) ;;
    *) set -- "$@" --rustls-provider "$(printf '%s' "$RUSTLS_PROVIDER" | tr -s ' ' ',')" ;;
  esac
  info "servers: $REMOTE, in $REMOTE_DIR (agent log: logs/$(basename "$REMOTE_LOG"))"
  info "clients connect to $CONNECT_HOST${REMOTE_ADDR:+ (REMOTE_ADDR)}"
  # shellcheck disable=SC2086
  $REMOTE_SSH -T -o ServerAliveInterval=15 -o ServerAliveCountMax=4 "$REMOTE" \
    "cd $REMOTE_DIR && exec sh ./pqcbench.sh $*" <"$_rmu_d/in" >"$_rmu_d/out" 2>"$REMOTE_LOG" &
  REMOTE_PID=$!
  exec 7>"$_rmu_d/in" 8<"$_rmu_d/out"
  REMOTE_UP=1
  # its env.txt, then "ready PROTO LIBS..."
  while remote_recv; do
    case $RREPLY in
      "env "*) printf 'remote %s\n' "${RREPLY#env }" >> "$OUTDIR/env.txt" ;;
      "ready "*) break ;;
    esac
  done
  # shellcheck disable=SC2086
  set -- $RREPLY
  [ "${2:-}" = "$REMOTE_PROTO" ] ||
    die "--remote: $REMOTE's pqcbench.sh speaks agent protocol ${2:-?}, this one $REMOTE_PROTO: update its checkout"
  shift 2
  _rmu_m=
  for _rmu_l in $LIBS; do
    case " $* " in *" $_rmu_l "*) ;; *) _rmu_m="${_rmu_m:+$_rmu_m }$_rmu_l" ;; esac
  done
  [ -z "$_rmu_m" ] ||
    die "--remote: $REMOTE has no $_rmu_m server (build it there with ./setup.sh, or leave it out here: --no-<library>, --rustls-provider)"
  info "remote host: $(sed -n 's/^remote host: //p' "$OUTDIR/env.txt")"
  _rmu_v=$(sed -n 's/^remote pqc-bench version: //p' "$OUTDIR/env.txt")
  [ "$_rmu_v" = "$PQCBENCH_VERSION" ] || warn "$REMOTE runs pqc-bench $_rmu_v, this machine $PQCBENCH_VERSION"

  # the path's round trip
  _rmu_rtt=$(remote_rtt); remote_sync "rtt-$$"
  if [ -n "$_rmu_rtt" ]; then
    echo "remote: $REMOTE ($CONNECT_HOST), servers in $REMOTE_DIR; rtt measured $_rmu_rtt ms ($REMOTE_RTT_HOW)" >> "$OUTDIR/env.txt"
    info "round trip: $_rmu_rtt ms ($REMOTE_RTT_HOW)"
    # as with --rtt: a server that exits after a refused handshake learns of
    # the refusal half a round trip later (ns_settle), and the handshake
    # timeout stays well above ~6 round trips
    NS_SETTLE=$(awk -v r="$_rmu_rtt" 'BEGIN { printf "%.3f", r / 1000 }')
    _rmu_to=$(awk -v r="$_rmu_rtt" 'BEGIN { printf "%d", r * 50 / 1000 + 1 }')
    if [ "$HS_TIMEOUT" -lt "$_rmu_to" ]; then
      warn "--remote: HS_TIMEOUT raised from $HS_TIMEOUT to $_rmu_to s"
      HS_TIMEOUT=$_rmu_to
      [ -n "$TO_CMD" ] && TO_CMD="${TO_CMD%% *} $HS_TIMEOUT"
    fi
  else
    echo "remote: $REMOTE ($CONNECT_HOST), servers in $REMOTE_DIR; rtt unknown" >> "$OUTDIR/env.txt"
    warn "--remote: couldn't time the round trip to $REMOTE (needs perl or python3)"
  fi
  info "  every sample costs several round trips: iterations $ITERATIONS / $MLDSA_ITERATIONS / $VERSIONS_ITERATIONS (key exchange / ML-DSA / versions)"
  [ "$DO_PRIM" = 1 ] &&
    info "  primitive benchmarks measure this machine (./pqcbench.sh --primitives-only on $REMOTE measures its CPU)"
  return 0
}

# measure the round trip again, fetch the server logs into logs/, and stop
# HOST's servers and agent (on_exit)
remote_down() {
  [ "$REMOTE_UP" = 1 ] || return 0
  # (after an interrupt a reply may still be on its way)
  remote_sync "done-$$" || return 0
  _rmd_ms=$(remote_rtt); remote_sync "rtt-end-$$" || return 0
  [ -z "$_rmd_ms" ] || echo "remote end: measured $_rmd_ms ms" >> "$OUTDIR/env.txt"
  _rmd_t=$OUTDIR/tools/remote/server-logs.tar
  if remote_fetch logs "$_rmd_t"; then
    if tar -xf "$_rmd_t" -C "$OUTDIR"; then rm -f "$_rmd_t"
    else warn "--remote: unpacking the server logs failed (${_rmd_t#"$OUTDIR"/})"; fi
  fi
  remote_req quit
  REMOTE_UP=0
  exec 7>&- 8<&-
  wait "$REMOTE_PID" 2>/dev/null
  rm -f "$OUTDIR/tools/remote/in" "$OUTDIR/tools/remote/out"
}

# --serve: HOST's side of --remote (requests on fd 4, replies on fd 3)
serve_reply() { printf '%s\n' "$*" >&3; }
# a library this agent runs (otherwise replies why not)
serve_lib() {
  case " $LIBS " in *" ${1:-} "*) return 0 ;; esac
  serve_reply "fail no ${1:-} server here"; return 1
}
# REL -> the path in this run directory; nothing for - or a path that leaves it
serve_path() {
  case $1 in
    -|/*|..|../*|*/../*|*/..) ;;
    *) printf '%s\n' "$OUTDIR/$1" ;;
  esac
}
serve_put() { # REL N, then N lines of base64
  _ag_t=$OUTDIR/tools/put.b64; _ag_i=0
  while [ "$_ag_i" -lt "$2" ] && IFS= read -r _ag_x <&4; do
    printf '%s\n' "$_ag_x"; _ag_i=$((_ag_i + 1))
  done > "$_ag_t"
  _ag_f=$(serve_path "$1")
  if [ -n "$_ag_f" ] && mkdir -p "$(dirname "$_ag_f")" && "$OPENSSL" base64 -d -in "$_ag_t" -out "$_ag_f"; then
    serve_reply ok
  else
    serve_reply "fail can't write $1"
  fi
  rm -f "$_ag_t"
}
serve_send_file() { # FILE -> data N + base64 lines, or none
  if [ -n "$1" ] && [ -f "$1" ] && _ag_b=$("$OPENSSL" base64 -e -in "$1"); then
    _ag_n=0; [ -n "$_ag_b" ] && _ag_n=$(printf '%s\n' "$_ag_b" | wc -l | tr -d ' ')
    serve_reply "data $_ag_n${_ag_b:+
$_ag_b}"
  else
    serve_reply none
  fi
}
serve_logs() {
  _ag_t=$OUTDIR/tools/server-logs.tar
  if ( cd "$OUTDIR" && ls logs/server-*.log >/dev/null 2>&1 && tar -cf "$_ag_t" logs/server-*.log ); then
    serve_send_file "$_ag_t"
  else
    serve_reply none
  fi
  rm -f "$_ag_t"
}
# IMPL PORT FUNCTION ARGS...: start IMPL's server with FUNCTION (start_server
# or vs_start_server), without the agent's fds 3 and 4
serve_launch() {
  _ag_s=$1; _ag_p=$2; shift 2
  # a server left over on the port (an earlier agent killed outright) would
  # answer in its place
  if [ "$PORT_TOOL" != none ] && port_listening "$_ag_p"; then
    serve_reply "fail port $_ag_p is already in use (a server left over from an earlier run?)"; return 0
  fi
  [ "$CAPTURE" = 1 ] && mkdir -p "$CAPDIR/keys"
  if "$@" 3>&- 4<&-; then
    eval "serve_reply \"ok \$SPID_$_ag_s\""
  else
    stop_server "$_ag_s"
    serve_reply fail
  fi
}
serve_start() { # IMPL GROUP LABEL PORT CERTK KEYS CERT KEY CA
  serve_lib "$1" || return 0
  eval "SPORT_$1=\$4"
  CERTK=$5; [ "$CERTK" = - ] && CERTK=
  CAPTURE=$6
  SRV_CERT=$(serve_path "$7"); SRV_KEY=$(serve_path "$8"); SRV_CA=$(serve_path "$9")
  serve_launch "$1" "$4" start_server "$1" "$2" "$3"
}
serve_vstart() { # IMPL LABEL PORT KEYS SV SG CERT KEY
  serve_lib "$1" || return 0
  eval "SPORT_$1=\$3"
  CAPTURE=$4; VS_SV=$5; VS_SG=$6
  VS_SCERT=$(serve_path "$7"); VS_SKEY=$(serve_path "$8")
  serve_launch "$1" "$3" vs_start_server "$1" "$2"
}
serve_loop() {
  # the client gone (ssh closes the pipes): stop every server, as quit does
  trap 'on_exit; exit 129' HUP
  trap 'on_exit; exit 141' PIPE
  CAPDIR=$OUTDIR/captures; mkdir -p "$OUTDIR/tools"
  while IFS= read -r _ag_x; do serve_reply "env $_ag_x"; done < "$OUTDIR/env.txt"
  serve_reply "ready $REMOTE_PROTO $LIBS"
  while IFS= read -r _ag_x <&4; do
    set -f
    # shellcheck disable=SC2086
    set -- $_ag_x
    set +f
    [ $# -gt 0 ] || continue
    _ag_c=$1; shift
    case $_ag_c in
      sync)   serve_reply "${1:-}" ;;
      put)    serve_put "${1:--}" "${2:-0}" ;;
      get)    serve_send_file "$(serve_path "${1:--}")" ;;
      logs)   serve_logs ;;
      start)  if [ $# -eq 9 ]; then serve_start "$@"; else serve_reply "fail bad request"; fi ;;
      vstart) if [ $# -eq 8 ]; then serve_vstart "$@"; else serve_reply "fail bad request"; fi ;;
      alive)  serve_lib "${1:-}" || continue
              eval "_ag_x=\$SPID_$1"
              if [ -n "$_ag_x" ] && kill -0 "$_ag_x" 2>/dev/null && port_listening "${2:-}"; then
                serve_reply yes
              else
                serve_reply no
              fi ;;
      stop)   serve_lib "${1:-}" || continue
              stop_server "$1"; serve_reply ok ;;
      quit)   stop_servers; serve_reply bye; return 0 ;;
      *)      serve_reply "fail unknown request $_ag_c" ;;
    esac
  done
}
on_exit() {
  # (--remote: remote_down has HOST's agent stop its servers)
  if [ "$REMOTE_UP" = 1 ]; then remote_down; else stop_servers; fi
  cap_stop_raw
  for _ox in $LIBS; do lib_has "$_ox" cleanup && "${_ox}_cleanup"; done
  netsim_down
}
trap on_exit EXIT
trap 'on_exit; exit 130' INT TERM

RESTARTS=0
# Library whose server just answered a client that exited 0 (or, in vs_time,
# refused it without exiting). The next ensure_server/vs_ensure for it then trusts
# `kill -0` alone: a port probe (lsof costs tens of ms) right before a sample
# also slows that sample down. With --remote it trusts the hint alone (asking
# HOST costs a round trip). After a failure the server is checked again; one
# check per hint.
SRV_SERVED=
# With --rtt or --remote, a server that exits after a failed handshake
# (wolfSSL, s2nd) still runs and listens until the client's refusal reaches it,
# half a round trip after the client exited; without a hint, wait a round trip
# first, or the next client finds the port closed.
ns_settle() { # IMPL
  [ -n "$NS_SETTLE" ] && [ "$SRV_SERVED" != "$1" ] || return 0
  sleep "$NS_SETTLE" 2>/dev/null || sleep 1
}
# is IMPL's server (PID, on PORT) up? (SRV_SERVED: see above)
srv_up() { # IMPL PID PORT
  [ -n "$2" ] || return 1
  if [ -n "$REMOTE" ]; then
    [ "$SRV_SERVED" = "$1" ] || remote_alive "$1" "$3"
  else
    kill -0 "$2" 2>/dev/null && { [ "$SRV_SERVED" = "$1" ] || port_listening "$3"; }
  fi
}
ensure_server() { # IMPL GROUP [LABEL]
  _es_label=${3:-$2}
  # a server that already failed to start for this label won't start on retry
  eval "_es_failed=\$START_FAILED_$1"
  [ "$_es_failed" = "$_es_label" ] && return 1
  eval "_es_pid=\$SPID_$1; _es_port=\$SPORT_$1; _es_grp=\$SGRP_$1"
  # not running with GROUP (never started, or a --pure-pq pair needs another
  # group): (re)start with it; not counted as a restart
  if [ "$_es_grp" != "$2" ]; then
    SRV_SERVED=
    stop_server "$1"
    start_server "$1" "$2" "$_es_label"
    return
  fi
  ns_settle "$1"
  if srv_up "$1" "$_es_pid" "$_es_port"; then
    SRV_SERVED=; return 0
  fi
  SRV_SERVED=
  stop_server "$1"
  RESTARTS=$((RESTARTS + 1))
  start_server "$1" "$2" "$_es_label"
}

# the next free port for each library's server
alloc_ports() {
  for _ap in $LIBS; do eval "SPORT_$_ap=\$NEXT_PORT"; NEXT_PORT=$((NEXT_PORT + 1)); done
  # netsim.sh shapes BASE_PORT .. BASE_PORT+999 only, and --remote's HOST lets
  # that range through
  if { [ "$NETSIM" = 1 ] || [ -n "$REMOTE" ]; } && [ "$NEXT_PORT" -gt $((BASE_PORT + 999)) ]; then
    die "more than 1000 server ports: past BASE_PORT..BASE_PORT+999 (netsim.sh shapes and --remote's HOST lets through); run fewer modes or libraries"
  fi
}

# one client run of IMPL: called directly in the timed loops (no subshell)
run_client() { # IMPL GROUP PORT [brief]
  _rc_impl=$1; shift
  "${_rc_impl}_client" "$@"
}

# status line of the server's HTTP response: the success check for every client
# (s2nc also echoes its request line, "GET / HTTP/1.0")
HTTP_RESPONSE='^HTTP/1\.[01] [0-9]'

# ----------------------------------------------------------------------------
# --inproc: hsloop clients (one process for all handshakes of a pair)
# ----------------------------------------------------------------------------
# run_inproc IMPL GROUP PORT COUNT CSV LOG: one hsloop client run (WARMUP +
# COUNT handshakes) against the server on PORT with the current CLI_CA,
# CLI_CERT/CLI_KEY and CERTK. The client writes one CSV row per timed handshake
# to CSV and a summary line ("init_ms=... failed=...") to LOG. Sets INPROC_INIT
# (ms, library start-up and client setup) and INPROC_FAILED.
run_inproc() {
  _ri_impl=$1; _ri_group=$2; _ri_count=$4; _ri_log=$6
  set -- "$("${_ri_impl}_inproc_bin")" --host "$CONNECT_HOST" --port "$3" --group "$2" --ca "$CLI_CA" --sni localhost \
    --count "$4" --warmup "$WARMUP" --timeout "$HS_TIMEOUT" --out "$5"
  [ -n "$CLI_CERT" ] && set -- "$@" --cert "$CLI_CERT" --key "$CLI_KEY"
  if lib_has "$_ri_impl" inproc_exec; then
    "${_ri_impl}_inproc_exec" "$_ri_group" "$@" >"$_ri_log" 2>&1
  else
    "$@" >"$_ri_log" 2>&1
  fi
  _ri_rc=$?
  _ri_line=$(grep '^init_ms=' "$_ri_log" | tail -n 1)
  INPROC_INIT=$(printf '%s\n' "$_ri_line" | sed -n 's/^init_ms=\([0-9.]*\).*/\1/p')
  INPROC_FAILED=$(printf '%s\n' "$_ri_line" | sed -n 's/.* failed=\([0-9]*\).*/\1/p')
  # no summary line: setup failed or the client crashed, so nothing was timed
  [ -n "$INPROC_FAILED" ] || INPROC_FAILED=$_ri_count
  return $_ri_rc
}

# inproc_pair KIND KEY CLIENT SERVER PORT GROUP LABEL COUNT [META_GROUP]: time
# one pair with the CLIENT's hsloop client and append to INRAW/INMETA (KIND kem)
# or MLINRAW/MLINMETA (KIND mldsa). KEY is the row prefix (group,cert, or
# profile,producer); LABEL is the server's label for ensure_server; META_GROUP
# (default GROUP) is the last column of the meta row (the requested group).
inproc_pair() {
  case " $INPROC_LIBS " in *" $3 "*) ;; *) return 0 ;; esac
  mkdir -p "$LOGDIR/inproc"
  _ip_csv=$LOGDIR/inproc/$1-$(printf '%s' "$2" | tr ',' '-')-$3-to-$4.csv
  _ip_log=${_ip_csv%.csv}.log
  if [ "$1" = kem ]; then _ip_raw=$INRAW; _ip_meta=$INMETA; else _ip_raw=$MLINRAW; _ip_meta=$MLINMETA; fi
  if ensure_server "$4" "$6" "$7"; then
    run_inproc "$3" "$6" "$5" "$8" "$_ip_csv" "$_ip_log"
    # a server that served a full run is up; after failures, check it again
    if [ "$INPROC_FAILED" = 0 ]; then SRV_SERVED=$4; else SRV_SERVED=; fi
  else
    INPROC_INIT=; INPROC_FAILED=$8; : > "$_ip_csv"
  fi
  [ -s "$_ip_csv" ] && awk -F, -v k="$2" -v c="$3" -v s="$4" 'NR>1 {print k "," c "," s "," $0}' "$_ip_csv" >> "$_ip_raw"
  printf '%s,%s,%s,%s,%s,%s\n' "$2" "$3" "$4" "$INPROC_FAILED" "$INPROC_INIT" "${9:-$6}" >> "$_ip_meta"
  _ip_med=$(awk -F, 'NR>1 && $9 == 1 {print $6}' "$_ip_csv" 2>/dev/null | median_of)
  _ip_fail=
  [ "$INPROC_FAILED" -gt 0 ] 2>/dev/null &&
    _ip_fail=", $INPROC_FAILED failed (see logs/inproc/$(basename "$_ip_log"))"
  printf '        in-process (hsloop-%s): median %s ms, init %s ms%s\n' "$3" "$_ip_med" \
    "${INPROC_INIT:--}" "$_ip_fail"
}

# CSV header of the per-handshake phase times hsloop writes (after the key)
INPROC_COLS="iteration,connect_ms,handshake_ms,response_ms,close_ms,total_ms,negotiated_group,version,ok,error"

# _is_col N: column N after the key of the rows in _is_rows (4 connect ...
# 8 total), one value per line
_is_col() { printf '%s\n' "$_is_rows" | awk -F, -v i="$(( _is_k + $1 ))" 'NF { print $i }'; }

# inproc_summary RAW META SUMMARY KEY_HEADER LAST_HEADER: per-pair summary of an
# in-process raw file whose rows start with two key columns (KEY_HEADER, e.g.
# group,cert), then client and server; LAST_HEADER names the meta rows' last column
inproc_summary() {
  _is_k=2
  {
    printf '%s,client,server,n,min_ms,median_ms,mean_ms,p95_ms,max_ms,median_connect_ms,' "$4"
    printf 'median_handshake_ms,median_response_ms,median_close_ms,init_ms,failed,%s\n' "$5"
  } > "$3"
  # meta rows: key1,key2,client,server,failed,init,group (read packs the rest into _is_f)
  while IFS=, read -r _is_a _is_b _is_c _is_d _is_e _is_f; do
    _is_key="$_is_a,$_is_b"; _is_cli=$_is_c; _is_srv=$_is_d; _is_fail=$_is_e
    _is_init=${_is_f%%,*}; _is_grp=${_is_f#*,}
    # ok rows of this pair; columns after the key: client, server, iteration, phases...
    _is_rows=$(awk -F, -v k="$_is_key" -v c="$_is_cli" -v s="$_is_srv" '
      NR > 1 && ($1 "," $2) == k && $3 == c && $4 == s && $13 == 1' "$1")

    _is_stats=$(_is_col 8 | stats_line 0 | cut -d, -f1-6)
    if [ -n "$_is_rows" ]; then
      _is_ph="$(_is_col 4 | median_of),$(_is_col 5 | median_of),$(_is_col 6 | median_of),$(_is_col 7 | median_of)"
    else
      _is_ph=",,,"
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$_is_key" "$_is_cli" "$_is_srv" "$_is_stats" \
      "$_is_ph" "${_is_init:-}" "$_is_fail" "$_is_grp" >> "$3"
  done < "$2"
}

STARTUP_DONE=0
measure_startup() { # IMPL
  _ms_f=$LOGDIR/startup-$1.txt; : > "$_ms_f"
  _ms_i=0
  while [ $_ms_i -lt 20 ]; do
    _ms_t0=$(now_ns)
    "$1_startup"
    _ms_t1=$(now_ns)
    elapsed_ms "$_ms_t0" "$_ms_t1" >> "$_ms_f"
    _ms_i=$((_ms_i + 1))
  done
  eval "STARTUP_$1=\$(median_of < \"\$_ms_f\")"
}
measure_startups() {
  [ "$STARTUP_DONE" = 1 ] && return 0
  _mss=
  for _msl in $LIBS; do
    measure_startup "$_msl"
    eval "_mss=\"\${_mss:+\$_mss, }\$_msl \$STARTUP_$_msl ms\""
  done
  STARTUP_DONE=1
  info "process startup baseline (median): $_mss"
  for _msl in $LIBS; do lib_has "$_msl" startup_note && "${_msl}_startup_note"; done
  return 0
}

write_req_cnf() { # FILE  (self-contained req config; system openssl.cnf not used)
  printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = unused' > "$1"
}

# ----------------------------------------------------------------------------
# KEM mode: handshake timing
# ----------------------------------------------------------------------------
# KEM mode server certificates: a CA and a server leaf for each --cert, issued
# by CERT_ISSUER, in CERTDIR/<cert>/ (ca.pem, srv.pem, srv.key.pem)
gen_certs() {
  if [ "$CERT_ISSUER" = wolfssl ]; then
    build_helper || die "--cert-issuer wolfssl: wolfSSL helper unavailable: $HELPER_WHY"
    [ "$HELPER_CERTGEN" = 1 ] || die "--cert-issuer wolfssl: $HELPER_CERTGEN_WHY"
  fi
  _gc_d=
  for _gc in $KEM_CERTS; do
    if [ "$_gc" = ec ]; then ML_CAL=ec; ML_LL=ec; else ml_split "${_gc#mldsa}"; fi
    _gc_log=$LOGDIR/certgen-$_gc.log
    "mk_chain_$CERT_ISSUER" "$CERTDIR/$_gc" "$ML_CAL" "$ML_LL" "PQC Bench CA" srv >"$_gc_log" 2>&1 ||
      die "certificate generation failed for $_gc (see logs/$(basename "$_gc_log"))"
    CERTK=$_gc; _gc_d="${_gc_d:+$_gc_d, }$(certk_desc)"
  done
  CERTK=ec
  info "server certificates: $_gc_d, issued by $(lib_name "$CERT_ISSUER") (CA + leaf in $CERTDIR/<cert>)"
}

# why CLIENT can't verify the server certificate in use (CERTK; prints nothing
# when it can): a wolfSSL-issued leaf without a subjectAltName, for a client
# that matches the server name against it only
kem_cert_skip() { # CLIENT
  [ "$CERT_ISSUER" = wolfssl ] && [ "$HELPER_SAN" != 1 ] || return 0
  eval "_kcs_so=\${LIBSANONLY_$1:-0}"
  [ "$_kcs_so" = 1 ] &&
    echo "the wolfSSL-issued server certificate has no subjectAltName and the $(lib_name "$1") client needs one (wolfSSL built without CPPFLAGS=-DWOLFSSL_ALT_NAMES; ./setup.sh wolfssl rebuilds it)"
  return 0
}

record_meta() { # GROUP CLIENT SERVER FAILS RESTARTS NOTE REQUESTED_GROUP  (cert: CERTK)
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$1" "$CERTK" "$2" "$3" "$4" "$5" "$(printf '%s' "$6" | tr ',\n' ';  ')" "$7" >> "$META"
}

# why CLIENT -> SERVER can't be tested with GROUP (prints nothing when it can):
# what the libraries' tables say (the client's first)
pair_skip() { # CLIENT SERVER GROUP
  _psk=$("$1_cli_skip" "$3")
  [ -n "$_psk" ] || _psk=$("$2_srv_skip" "$3")
  [ -z "$_psk" ] || printf '%s\n' "$_psk"
}
# does IMPL's build lack GROUP? (only libraries that probe their build can)
lib_lacks() { # IMPL GROUP
  lib_has "$1" has_group || return 1
  if "$1_has_group" "$2"; then return 1; fi
  return 0
}
# the first of CLIENT and SERVER whose build lacks GROUP -> LACKS (empty if none).
# Call directly, not in $(...): the build probes cache.
pair_lacks() { # CLIENT SERVER GROUP
  LACKS=
  for _pl_l in "$1" "$2"; do
    if lib_lacks "$_pl_l" "$3"; then LACKS=$_pl_l; return 0; fi
  done
  return 1
}

# --pure-pq: the group CLIENT -> SERVER uses for GROUP (pure ML-KEM): GROUP
# when both libraries can use it, else the first pq_fallbacks entry they can.
# -> PQ_GROUP (empty if none), PQ_WHY ("<group>: <reason>; ..." for every group
# passed over). Call directly, not in $(...): the build probes cache.
pq_pick() { # CLIENT SERVER GROUP
  PQ_GROUP=; PQ_WHY=
  for _pp_g in $3 $(pq_fallbacks "$3"); do
    _pp_why=$(pair_skip "$1" "$2" "$_pp_g")
    if [ -z "$_pp_why" ] && pair_lacks "$1" "$2" "$_pp_g"; then
      _pp_why="this $(lib_name "$LACKS") build lacks it"
    fi
    if [ -z "$_pp_why" ]; then PQ_GROUP=$_pp_g; return 0; fi
    PQ_WHY="${PQ_WHY:+$PQ_WHY; }$_pp_g: $_pp_why"
  done
  return 1
}

run_handshakes() {
  hdr "Handshakes (key exchange): $ITERATIONS timed runs per pair (+$WARMUP warmup)"
  if [ "$PURE_PQ" = 1 ]; then
    info "--pure-pq: groups $GROUP_ORDER; a pair that can't use one falls back to a hybrid, then a classical group"
  fi
  gen_certs
  SRV_CA=; CLI_CERT=; CLI_KEY=
  measure_startups

  RAW=$OUTDIR/handshakes_raw.csv
  META=$LOGDIR/pairs.csv
  echo "group,cert,client,server,iteration,ms" > "$RAW"
  : > "$META"
  INRAW=$OUTDIR/handshakes_inproc_raw.csv; INMETA=$LOGDIR/inproc-pairs.csv
  if [ "$INPROC" = 1 ]; then echo "group,cert,client,server,$INPROC_COLS" > "$INRAW"; : > "$INMETA"; fi

  # each group with each certificate in turn, so a group's certificates are
  # timed close together; the servers restart with each certificate
  for g in $GROUP_ORDER; do
    if ! group_known "$g"; then
      warn "group '$g' is unknown (known: $(echo $GROUPS_KNOWN)); skipping"; continue
    fi
    alloc_ports
    for CERTK in $KEM_CERTS; do
      SRV_CERT=$CERTDIR/$CERTK/srv.pem; SRV_KEY=$CERTDIR/$CERTK/srv.key.pem; CLI_CA=$CERTDIR/$CERTK/ca.pem
      printf '\n%s%s%s  (%s server certificate)\n' "$C_B" "$g" "$C_0" "$(certk_desc)"
      kem_matrix "$g"
      stop_servers
    done
  done
  CERTK=ec
}

# every client -> server pair with GROUP and the certificate in use (CERTK);
# servers are labelled <group>-<cert>
kem_matrix() { # GROUP
  g=$1
  for srv in $LIBS; do
    [ -n "$("${srv}_srv_skip" "$g")" ] && continue
    # (e.g. the wolfSSL FIPS build has no X25519MLKEM768)
    [ "$PURE_PQ" != 1 ] && lib_lacks "$srv" "$g" && continue
    start_server "$srv" "$g" "$g-$CERTK"
  done

  for srv in $LIBS; do
    eval "sport=\$SPORT_$srv"
    for cli in $LIBS; do
      printf "  %-${LIBW}s -> %-${LIBW}s " "$cli" "$srv"
      _skip=$(kem_cert_skip "$cli")
      if [ -n "$_skip" ]; then
        record_meta "$g" "$cli" "$srv" 0 0 "skipped ($_skip)" "$g"
        echo "skipped"; continue
      fi
      # eg = the group this pair uses: $g, or with --pure-pq a fallback (fb says why)
      eg=$g; fb=
      if [ "$PURE_PQ" = 1 ]; then
        if ! pq_pick "$cli" "$srv" "$g"; then
          record_meta "$g" "$cli" "$srv" 0 0 "skipped (no usable group: $PQ_WHY)" "$g"
          echo "skipped"; continue
        fi
        eg=$PQ_GROUP
        if [ "$eg" != "$g" ]; then
          fb="pure-PQ fallback to $(group_kind "$eg") $eg ($PQ_WHY)"
          printf '%s[%s %s]%s ' "$C_YL" "$(group_kind "$eg")" "$eg" "$C_0"
          # another group's fallback may have timed this cell already
          eval "_kt=\${KEM_TIMED_$(ptag "$eg")_$(ptag "$CERTK")_${cli}_$srv:-}"
          if [ -n "$_kt" ]; then
            record_meta "$eg" "$cli" "$srv" - - "$fb; timed with the $_kt row" "$g"
            echo "timed with $_kt"; continue
          fi
        fi
      else
        _skip=$(pair_skip "$cli" "$srv" "$g")
        if [ -z "$_skip" ] && pair_lacks "$cli" "$srv" "$g"; then
          _skip="this $(lib_name "$LACKS") build lacks $g"
        fi
        if [ -n "$_skip" ]; then
          record_meta "$g" "$cli" "$srv" 0 0 "skipped ($_skip)" "$g"
          echo "skipped"; continue
        fi
      fi
      _lbl=$eg-$CERTK

      # preflight (also confirms the negotiated group where possible)
      pflog=$LOGDIR/preflight-$cli-to-$srv-$_lbl.log; rc=1; i=0
      CAP_LABEL=$_lbl; cap_begin "kem/$CERTK/$eg/$cli-to-$srv" "$sport"
      while [ $i -lt 3 ]; do
        ensure_server "$srv" "$eg" "$_lbl" || break
        if run_client "$cli" "$eg" "$sport" brief >"$pflog" 2>&1; then rc=0; SRV_SERVED=$srv; break; fi
        sleep 1
        i=$((i + 1))
      done
      cap_end
      if [ $rc -ne 0 ]; then
        eval "_pf_srvfail=\$START_FAILED_$srv"
        _why=
        if [ "$_pf_srvfail" = "$_lbl" ]; then
          _why="$srv server failed to start"
        elif lib_has "$cli" preflight_why; then
          _why=$("${cli}_preflight_why" "$pflog" "$eg")
        fi
        [ -n "$_why" ] || _why="handshake failed"
        _pf_ls=$cli; [ "$srv" = "$cli" ] || _pf_ls="$cli $srv"
        for _pf_l in $_pf_ls; do
          lib_has "$_pf_l" why_hint && _why=$("${_pf_l}_why_hint" "$eg" "$_why")
        done
        record_meta "$eg" "$cli" "$srv" - - "${fb:+$fb; }FAILED preflight: $_why; see logs/$(basename "$pflog")" "$g"
        printf '%spreflight failed%s (%s)\n' "$C_RD" "$C_0" "$_why"; continue
      fi
      # how sure the group is: the client confirms it, or the server pins it
      note=
      lib_has "$cli" confirm && note=$("${cli}_confirm" "$pflog" "$eg")
      [ -z "$note" ] && lib_has "$srv" srv_pin_note && note=$("${srv}_srv_pin_note")
      [ -n "$note" ] || note="group set by client flags only"
      [ -n "$fb" ] && note="$fb; $note"

      i=0
      while [ $i -lt "$WARMUP" ]; do
        ensure_server "$srv" "$eg" "$_lbl"
        run_client "$cli" "$eg" "$sport" >/dev/null 2>&1 && SRV_SERVED=$srv
        i=$((i + 1))
      done

      RESTARTS=0; fails=0; i=1
      while [ $i -le "$ITERATIONS" ]; do
        if ensure_server "$srv" "$eg" "$_lbl"; then
          t0=$(now_ns)
          run_client "$cli" "$eg" "$sport" >/dev/null 2>&1; rc=$?
          t1=$(now_ns)
          if [ $rc -eq 0 ]; then
            SRV_SERVED=$srv
            printf '%s,%s,%s,%s,%d,%s\n' "$eg" "$CERTK" "$cli" "$srv" "$i" "$(elapsed_ms "$t0" "$t1")" >> "$RAW"
          else
            fails=$((fails + 1))
          fi
        else
          fails=$((fails + 1))
        fi
        [ $((i % 10)) -eq 0 ] && printf '.'
        i=$((i + 1))
      done
      record_meta "$eg" "$cli" "$srv" "$fails" "$RESTARTS" "$note" "$g"
      [ -n "$fb" ] && eval "KEM_TIMED_$(ptag "$eg")_$(ptag "$CERTK")_${cli}_$srv=\$g"
      if [ "$fails" -gt 0 ]; then echo " done ($fails failed)"; else echo " done"; fi
      [ "$INPROC" = 1 ] && inproc_pair kem "$eg,$CERTK" "$cli" "$srv" "$sport" "$eg" "$_lbl" "$ITERATIONS" "$g"
    done
  done
}

summarize() {
  SUMMARY=$OUTDIR/handshakes_summary.csv
  echo "group,cert,client,server,n,min_ms,median_ms,mean_ms,p95_ms,max_ms,adj_median_ms,failed,server_restarts,note,requested_group" > "$SUMMARY"
  while IFS=, read -r g crt cli srv fails rst note req; do
    eval "base=\$STARTUP_$cli"
    stats=$(awk -F, -v g="$g" -v k="$crt" -v c="$cli" -v s="$srv" \
              'NR>1 && $1==g && $2==k && $3==c && $4==s {print $6}' "$RAW" | stats_line "$base")
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$g" "$crt" "$cli" "$srv" "$stats" "$fails" "$rst" "$note" "$req" >> "$SUMMARY"
  done < "$META"

  hdr "Handshake summary, key exchange (ms)"
  if [ "$PURE_PQ" = 1 ]; then
    # requested group first; group = what the pair used
    awk -F, -v OFS=, '{ o = $15; for (i = 1; i <= 12; i++) o = o OFS $i; print o }' "$SUMMARY" | print_table
  else
    cut -d, -f1-12 "$SUMMARY" | print_table
  fi
  # notes on how the group was set, and extra key shares a client's policy sends
  _notes=$(awk -F, 'NR>1 && $15 == $1 && ($14 !~ /confirmed|pinned/ || $14 ~ /key share/) {print "  " $1 " [" $2 "] " $3 "->" $4 ": " $14}' "$SUMMARY")
  if [ -n "$_notes" ]; then printf '\nNotes:\n%s\n' "$_notes"; fi
  _fbs=$(awk -F, 'NR>1 && $15 != $1 {print "  " $15 " [" $2 "] " $3 "->" $4 ": " $14}' "$SUMMARY")
  if [ -n "$_fbs" ]; then printf '\nPure-PQ fallbacks (pairs that could not use the requested group):\n%s\n' "$_fbs"; fi
  printf '\nadj_median_ms = median minus client process-startup baseline.\n'
  if [ "$INPROC" = 1 ] && [ -s "$INMETA" ]; then
    INSUM=$OUTDIR/handshakes_inproc_summary.csv
    inproc_summary "$INRAW" "$INMETA" "$INSUM" group,cert requested_group
    hdr "Handshake summary, key exchange, in-process hsloop clients (ms)"
    cut -d, -f1-5,7,9,12,15,16 "$INSUM" | print_table
    printf '\nmedian_ms = whole handshake sample (connect + handshake + request/response + close),\n'
    printf 'all in one client process; init_ms = library start-up and client setup, once per run.\n'
  fi
}

# ----------------------------------------------------------------------------
# ML-DSA mode: wolfSSL helper (compiled against the wolfSSL under test)
# ----------------------------------------------------------------------------
write_helper_source() {
cat <<'EOF_MLDSA_HELPER'
/* mldsa-helper: wolfSSL side of the pqc-bench ML-DSA interop checks.
 *   genkey    L key.der pub.der                  new key pair (PKCS#8 + SPKI DER)
 *   checkkey  L key.der                          decode a private key, sign with it
 *   checkpub  L pub.der                          decode a public key (SPKI)
 *   sign      L key.der msg sig                  pure ML-DSA, empty context
 *   verify    L pub.der msg sig                  exit 0 valid, 1 invalid
 *   mkca      L key.der cert.der CN              new CA key + self-signed cert
 *   mkleaf    L CA_L cakey.der cacert CN server|client key.der cert.der
 *             (with WOLFSSL_ALT_NAMES: the subjectAltName OpenSSL's leaves get)
 *   verifycert ca-cert leaf-cert                 chain check with CertManager
 *   ecmkca    key.der cert.der CN                ECDSA P-256 CA (keys: SEC1 DER), for
 *   ecmkleaf  cakey.der cacert CN server|client key.der cert.der
 *             key-exchange mode's --cert ec with --cert-issuer wolfssl
 * L is 44, 65 or 87. Certificates may be PEM or DER; keys are DER.
 * Exit codes: 0 ok, 1 check failed, 2 usage/IO error, 3 unsupported by build.
 * Uses the legacy wc_dilithium_* names, which current wolfSSL still maps to
 * its wc_MlDsaKey_* API, so this builds against 5.7.x and later. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SZ 32768
static const byte MSG_DEFAULT[] = "pqc-bench selftest";

static int die2(const char* m) { fprintf(stderr, "error: %s\n", m); return 2; }
static int fail(const char* what, int ret)
{
    fprintf(stderr, "%s failed: %d (%s)\n", what, ret, wc_GetErrorString(ret));
    return 1;
}
static int parse_level(const char* s)
{
    if (strcmp(s, "44") == 0) return 2;
    if (strcmp(s, "65") == 0) return 3;
    if (strcmp(s, "87") == 0) return 5;
    return -1;
}
static int key_type(int l)
{
    return l == 2 ? ML_DSA_LEVEL2_TYPE : l == 3 ? ML_DSA_LEVEL3_TYPE : ML_DSA_LEVEL5_TYPE;
}
#ifdef WOLFSSL_CERT_GEN
static int sig_type(int l)
{
    return l == 2 ? CTC_ML_DSA_LEVEL2 : l == 3 ? CTC_ML_DSA_LEVEL3 : CTC_ML_DSA_LEVEL5;
}
#endif
static int read_file(const char* path, byte** out, word32* len)
{
    FILE* f = fopen(path, "rb");
    long n;
    if (f == NULL) return -1;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f); return -1;
    }
    *out = (byte*)malloc((size_t)n + 1);
    if (*out == NULL) { fclose(f); return -1; }
    if (n > 0 && fread(*out, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(*out); return -1; }
    (*out)[n] = 0;
    fclose(f);
    *len = (word32)n;
    return 0;
}
static int write_file(const char* path, const byte* b, word32 len)
{
    FILE* f = fopen(path, "wb");
    int ok;
    if (f == NULL) return -1;
    ok = fwrite(b, 1, len, f) == len;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}
static int is_pem(const byte* b, word32 len)
{
    return len > 10 && memcmp(b, "-----BEGIN", 10) == 0;
}
static int load_cert_der(const char* path, byte* der, word32* derLen)
{
    byte* raw; word32 rawLen; int ret;
    if (read_file(path, &raw, &rawLen) != 0) return -1;
    if (is_pem(raw, rawLen)) {
        ret = wc_CertPemToDer(raw, (int)rawLen, der, (int)*derLen, CERT_TYPE);
        free(raw);
        if (ret <= 0) return ret == 0 ? -1 : ret;
        *derLen = (word32)ret;
        return 0;
    }
    if (rawLen > *derLen) { free(raw); return -1; }
    memcpy(der, raw, rawLen);
    *derLen = rawLen;
    free(raw);
    return 0;
}
static int init_key(dilithium_key* key, int level)
{
    int ret = wc_dilithium_init(key);
    if (ret == 0) ret = wc_dilithium_set_level(key, (byte)level);
    return ret;
}
static int load_priv(dilithium_key* key, int level, const char* path)
{
    byte* buf; word32 len, idx = 0; int ret;
    if (read_file(path, &buf, &len) != 0) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    ret = init_key(key, level);
    if (ret == 0) ret = wc_Dilithium_PrivateKeyDecode(buf, &idx, key, len);
    free(buf);
    if (ret != 0) return fail("private key decode", ret);
    return 0;
}
static int load_pub(dilithium_key* key, int level, const char* path)
{
    byte* buf; word32 len, idx = 0; int ret;
    if (read_file(path, &buf, &len) != 0) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    ret = init_key(key, level);
    if (ret == 0) ret = wc_Dilithium_PublicKeyDecode(buf, &idx, key, len);
    free(buf);
    if (ret != 0) return fail("public key decode", ret);
    return 0;
}
static int write_keypair(dilithium_key* key, const char* privPath, const char* pubPath)
{
    static byte der[BUF_SZ];
    int n = wc_Dilithium_PrivateKeyToDer(key, der, sizeof(der));
    if (n <= 0) return fail("PrivateKeyToDer", n);
    if (write_file(privPath, der, (word32)n) != 0) return die2("cannot write private key");
    if (pubPath != NULL) {
        n = wc_Dilithium_PublicKeyToDer(key, der, sizeof(der), 1);
        if (n <= 0) return fail("PublicKeyToDer", n);
        if (write_file(pubPath, der, (word32)n) != 0) return die2("cannot write public key");
    }
    return 0;
}
static int make_key(dilithium_key* key, int level, WC_RNG* rng)
{
    int ret = init_key(key, level);
    if (ret == 0) ret = wc_dilithium_make_key(key, rng);
    if (ret != 0) return fail("key generation", ret);
    return 0;
}
static int sign_buf(dilithium_key* key, const byte* msg, word32 msgLen,
                    byte* sig, word32* sigLen, WC_RNG* rng)
{
    return wc_dilithium_sign_ctx_msg(NULL, 0, msg, msgLen, sig, sigLen, key, rng);
}
#ifdef WOLFSSL_CERT_GEN
static int issue(Cert* cert, int subjLevel, dilithium_key* subjKey,
                 int signLevel, dilithium_key* signKey, WC_RNG* rng,
                 const char* outPath)
{
    static byte der[BUF_SZ];
    int ret;
    /* must be set before MakeCert: it is encoded into the TBS body too */
    cert->sigType = sig_type(signLevel);
    ret = wc_MakeCert_ex(cert, der, sizeof(der), key_type(subjLevel), subjKey, rng);
    if (ret < 0) return fail("MakeCert", ret);
    ret = wc_SignCert_ex(cert->bodySz, cert->sigType, der, sizeof(der),
                         key_type(signLevel), signKey, rng);
    if (ret < 0) return fail("SignCert", ret);
    if (write_file(outPath, der, (word32)ret) != 0) return die2("cannot write certificate");
    return 0;
}
#ifdef WOLFSSL_ALT_NAMES
/* the subjectAltName of the OpenSSL-issued leaves, as GeneralNames DER:
 * DNS:localhost, IP:127.0.0.1 (server) or DNS:pqc-bench-client (client) */
static void set_alt_names(Cert* cert, int server)
{
    static const byte srv[] = { 0x30, 0x11, 0x82, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
                                0x87, 0x04, 127, 0, 0, 1 };
    static const byte cli[] = { 0x30, 0x12, 0x82, 0x10, 'p', 'q', 'c', '-', 'b', 'e', 'n', 'c', 'h',
                                '-', 'c', 'l', 'i', 'e', 'n', 't' };
    cert->altNamesSz = server ? (int)sizeof(srv) : (int)sizeof(cli);
    memcpy(cert->altNames, server ? srv : cli, (size_t)cert->altNamesSz);
}
#endif
#endif
#if defined(WOLFSSL_CERT_GEN) && defined(HAVE_ECC)
/* ECDSA P-256 certificates; keys initialised by the caller */
static int ec_new_key(ecc_key* key, WC_RNG* rng, const char* path)
{
    static byte der[BUF_SZ];
    int n, ret = wc_ecc_make_key_ex(rng, 32, key, ECC_SECP256R1);
    if (ret != 0) return fail("ECC key generation", ret);
    n = wc_EccKeyToDer(key, der, sizeof(der));
    if (n <= 0) return fail("EccKeyToDer", n);
    if (write_file(path, der, (word32)n) != 0) return die2("cannot write private key");
    return 0;
}
static int ec_load_key(ecc_key* key, const char* path)
{
    byte* buf; word32 len, idx = 0; int ret;
    if (read_file(path, &buf, &len) != 0) { fprintf(stderr, "cannot read %s\n", path); return 2; }
    ret = wc_EccPrivateKeyDecode(buf, &idx, key, len);
    free(buf);
    if (ret != 0) return fail("ECC private key decode", ret);
    return 0;
}
static int ec_issue(Cert* cert, ecc_key* subjKey, ecc_key* signKey, WC_RNG* rng,
                    const char* outPath)
{
    static byte der[BUF_SZ];
    int ret;
    cert->sigType = CTC_SHA256wECDSA;
    ret = wc_MakeCert_ex(cert, der, sizeof(der), ECC_TYPE, subjKey, rng);
    if (ret < 0) return fail("MakeCert", ret);
    ret = wc_SignCert_ex(cert->bodySz, cert->sigType, der, sizeof(der), ECC_TYPE, signKey, rng);
    if (ret < 0) return fail("SignCert", ret);
    if (write_file(outPath, der, (word32)ret) != 0) return die2("cannot write certificate");
    return 0;
}
/* ecmkca KEY CERT CN | ecmkleaf CAKEY CACERT CN server|client KEY CERT */
static int ec_cmd(int argc, char** argv)
{
    static byte caDer[BUF_SZ];
    word32 caDerLen = sizeof(caDer);
    ecc_key key, caKey;
    WC_RNG rng;
    Cert cert;
    int isCa = strcmp(argv[1], "ecmkca") == 0, ret;
    if (isCa ? argc != 5 : argc != 8)
        return die2("ecmkca KEY CERT CN, or ecmkleaf CAKEY CACERT CN server|client KEY CERT");
    if (!isCa && load_cert_der(argv[3], caDer, &caDerLen) != 0) return fail("CA certificate parse", -1);
    if (wc_InitRng(&rng) != 0) return die2("RNG init");
    if (wc_ecc_init(&key) != 0 || wc_ecc_init(&caKey) != 0) return die2("ECC init");
    ret = isCa ? 0 : ec_load_key(&caKey, argv[2]);
    if (ret == 0) ret = ec_new_key(&key, &rng, isCa ? argv[2] : argv[6]);
    if (ret == 0 && (ret = wc_InitCert(&cert)) != 0) ret = fail("InitCert", ret);
    if (ret == 0) {
        strncpy(cert.subject.commonName, argv[4], CTC_NAME_SIZE - 1);
        cert.daysValid = 30;
        if (isCa) {
            cert.isCA = 1;
            cert.selfSigned = 1;
        #ifdef WOLFSSL_CERT_EXT
            wc_SetKeyUsage(&cert, "keyCertSign,cRLSign");
            wc_SetSubjectKeyIdFromPublicKey_ex(&cert, ECC_TYPE, &key);
        #endif
            ret = ec_issue(&cert, &key, &key, &rng, argv[3]);
        } else {
            int r = wc_SetIssuerBuffer(&cert, caDer, (int)caDerLen);
            if (r != 0) ret = fail("SetIssuerBuffer", r);
        #ifdef WOLFSSL_CERT_EXT
            wc_SetKeyUsage(&cert, "digitalSignature");
            wc_SetExtKeyUsage(&cert, strcmp(argv[5], "client") == 0 ? "clientAuth" : "serverAuth");
            wc_SetSubjectKeyIdFromPublicKey_ex(&cert, ECC_TYPE, &key);
            wc_SetAuthKeyIdFromCert(&cert, caDer, (int)caDerLen);
        #endif
        #ifdef WOLFSSL_ALT_NAMES
            set_alt_names(&cert, strcmp(argv[5], "client") != 0);
        #endif
            if (ret == 0) ret = ec_issue(&cert, &key, &caKey, &rng, argv[7]);
        }
    }
    wc_ecc_free(&key);
    wc_ecc_free(&caKey);
    wc_FreeRng(&rng);
    return ret;
}
#endif
int main(int argc, char** argv)
{
    static byte sig[BUF_SZ], der[BUF_SZ];
    dilithium_key key, key2;
    WC_RNG rng;
    int level, ret = 2;
    const char* cmd;

    if (argc < 2) return die2("usage: see source header");
    cmd = argv[1];
    /* wolfSSL_Init first: in FIPS builds (WC_RNG_SEED_CB) it installs the RNG
     * seed callback, without which wc_InitRng fails */
    wolfSSL_Init();

    if (strcmp(cmd, "verifycert") == 0) {
        static byte ca[BUF_SZ], leaf[BUF_SZ];
        word32 caLen = sizeof(ca), leafLen = sizeof(leaf);
        WOLFSSL_CERT_MANAGER* cm;
        if (argc != 4) return die2("verifycert CA LEAF");
        if (load_cert_der(argv[2], ca, &caLen) != 0) return fail("CA certificate parse", -1);
        if (load_cert_der(argv[3], leaf, &leafLen) != 0) return fail("leaf certificate parse", -1);
        cm = wolfSSL_CertManagerNew();
        if (cm == NULL) return die2("CertManagerNew");
        ret = wolfSSL_CertManagerLoadCABuffer(cm, ca, (long)caLen, WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) { wolfSSL_CertManagerFree(cm); return fail("load CA", ret); }
        ret = wolfSSL_CertManagerVerifyBuffer(cm, leaf, (long)leafLen, WOLFSSL_FILETYPE_ASN1);
        wolfSSL_CertManagerFree(cm);
        wolfSSL_Cleanup();
        if (ret != WOLFSSL_SUCCESS) return fail("verify", ret);
        return 0;
    }
    if (strcmp(cmd, "ecmkca") == 0 || strcmp(cmd, "ecmkleaf") == 0) {
#if defined(WOLFSSL_CERT_GEN) && defined(HAVE_ECC)
        return ec_cmd(argc, argv);
#else
        fprintf(stderr, "unsupported: wolfSSL built without certificate generation (--enable-certgen) or ECC\n");
        return 3;
#endif
    }

    if (argc < 3 || (level = parse_level(argv[2])) < 0)
        return die2("first argument after the command must be 44, 65 or 87");
    if (wc_InitRng(&rng) != 0) return die2("RNG init");

    if (strcmp(cmd, "genkey") == 0 && argc == 5) {
        ret = make_key(&key, level, &rng);
        if (ret == 0) ret = write_keypair(&key, argv[3], argv[4]);
        wc_dilithium_free(&key);
    }
    else if (strcmp(cmd, "checkkey") == 0 && argc == 4) {
        ret = load_priv(&key, level, argv[3]);
        if (ret == 0) {
            word32 sigLen = sizeof(sig);
            int r = sign_buf(&key, MSG_DEFAULT, sizeof(MSG_DEFAULT) - 1, sig, &sigLen, &rng);
            ret = r == 0 ? 0 : fail("sign with decoded key", r);
        }
        wc_dilithium_free(&key);
    }
    else if (strcmp(cmd, "checkpub") == 0 && argc == 4) {
        ret = load_pub(&key, level, argv[3]);
        wc_dilithium_free(&key);
    }
    else if (strcmp(cmd, "sign") == 0 && argc == 6) {
        byte* msg; word32 msgLen, sigLen = sizeof(sig);
        if (read_file(argv[4], &msg, &msgLen) != 0) { ret = die2("cannot read message"); }
        else {
            ret = load_priv(&key, level, argv[3]);
            if (ret == 0) {
                int r = sign_buf(&key, msg, msgLen, sig, &sigLen, &rng);
                if (r != 0) ret = fail("sign", r);
                else if (write_file(argv[5], sig, sigLen) != 0) ret = die2("cannot write signature");
            }
            wc_dilithium_free(&key);
            free(msg);
        }
    }
    else if (strcmp(cmd, "verify") == 0 && argc == 6) {
        byte *msg = NULL, *s = NULL; word32 msgLen, sLen; int res = 0;
        if (read_file(argv[4], &msg, &msgLen) != 0 || read_file(argv[5], &s, &sLen) != 0) {
            ret = die2("cannot read message or signature");
        } else {
            ret = load_pub(&key, level, argv[3]);
            if (ret == 0) {
                int r = wc_dilithium_verify_ctx_msg(s, sLen, NULL, 0, msg, msgLen, &res, &key);
                if (r != 0) ret = fail("verify", r);
                else if (res != 1) { fprintf(stderr, "signature invalid\n"); ret = 1; }
            }
            wc_dilithium_free(&key);
        }
        free(msg); free(s);
    }
    else if (strcmp(cmd, "mkca") == 0 && argc == 6) {
#ifdef WOLFSSL_CERT_GEN
        Cert cert;
        ret = make_key(&key, level, &rng);
        if (ret == 0) ret = write_keypair(&key, argv[3], NULL);
        if (ret == 0 && wc_InitCert(&cert) == 0) {
            strncpy(cert.subject.commonName, argv[5], CTC_NAME_SIZE - 1);
            cert.isCA = 1;
            cert.daysValid = 30;
            cert.selfSigned = 1;
        #ifdef WOLFSSL_CERT_EXT
            wc_SetKeyUsage(&cert, "keyCertSign,cRLSign");
            wc_SetSubjectKeyIdFromPublicKey_ex(&cert, key_type(level), &key);
        #endif
            ret = issue(&cert, level, &key, level, &key, &rng, argv[4]);
        }
        wc_dilithium_free(&key);
#else
        fprintf(stderr, "unsupported: wolfSSL built without certificate generation (--enable-certgen)\n");
        ret = 3;
#endif
    }
    else if (strcmp(cmd, "mkleaf") == 0 && argc == 10) {
#ifdef WOLFSSL_CERT_GEN
        Cert cert;
        int caLevel = parse_level(argv[3]);
        word32 caDerLen = sizeof(der);
        if (caLevel < 0) { ret = die2("CA level must be 44, 65 or 87"); }
        else if (load_cert_der(argv[5], der, &caDerLen) != 0) { ret = fail("CA certificate parse", -1); }
        else {
            ret = load_priv(&key2, caLevel, argv[4]);
            if (ret == 0) ret = make_key(&key, level, &rng);
            if (ret == 0) ret = write_keypair(&key, argv[8], NULL);
            if (ret == 0 && wc_InitCert(&cert) == 0) {
                int r;
                strncpy(cert.subject.commonName, argv[6], CTC_NAME_SIZE - 1);
                cert.daysValid = 30;
                r = wc_SetIssuerBuffer(&cert, der, (int)caDerLen);
                if (r != 0) ret = fail("SetIssuerBuffer", r);
            #ifdef WOLFSSL_CERT_EXT
                wc_SetKeyUsage(&cert, "digitalSignature");
                wc_SetExtKeyUsage(&cert, strcmp(argv[7], "client") == 0 ? "clientAuth" : "serverAuth");
                wc_SetSubjectKeyIdFromPublicKey_ex(&cert, key_type(level), &key);
                wc_SetAuthKeyIdFromCert(&cert, der, (int)caDerLen);
            #endif
            #ifdef WOLFSSL_ALT_NAMES
                set_alt_names(&cert, strcmp(argv[7], "client") != 0);
            #endif
                if (ret == 0) ret = issue(&cert, level, &key, caLevel, &key2, &rng, argv[9]);
            }
            wc_dilithium_free(&key);
            wc_dilithium_free(&key2);
        }
#else
        fprintf(stderr, "unsupported: wolfSSL built without certificate generation (--enable-certgen)\n");
        ret = 3;
#endif
    }
    else {
        ret = die2("unknown command or wrong number of arguments");
    }

    wc_FreeRng(&rng);
    return ret;
}
EOF_MLDSA_HELPER
}

HELPER=; HELPER_WHY=; HELPER_CERTGEN=0; HELPER_CERTGEN_WHY=; HELPER_SAN=0
build_helper() {
  # built already (key-exchange mode's --cert-issuer wolfssl, then ML-DSA mode)
  [ -n "$HELPER" ] && return 0
  if [ -n "$MLDSA_HELPER" ]; then
    if [ -x "$MLDSA_HELPER" ]; then HELPER=$MLDSA_HELPER
    else HELPER_WHY="MLDSA_HELPER=$MLDSA_HELPER is not executable"; return 1; fi
  else
    # CC may carry arguments (e.g. "xcrun clang" or "clang -arch arm64"),
    # so look up only its first word.
    _bh_cc=${CC:-cc}
    _bh_cc1=${_bh_cc%% *}
    if ! have "$_bh_cc1"; then
      HELPER_WHY="C compiler '$_bh_cc1' not found (CC=${CC:-unset}); set CC to your compiler"; return 1
    fi
    mkdir -p "$OUTDIR/tools"
    _bh_src=$OUTDIR/tools/mldsa_helper.c
    _bh_bin=$OUTDIR/tools/mldsa-helper
    _bh_log=$LOGDIR/mldsa-helper-build.log
    write_helper_source > "$_bh_src"
    _bh_cflags=; _bh_libs=
    if [ -n "$WOLFSSL_DIR" ] && [ -f "$WOLFSSL_DIR/wolfssl/options.h" ]; then
      _bh_cflags="-I$WOLFSSL_DIR"
      if [ -f "$WOLFSSL_DIR/src/.libs/libwolfssl.a" ]; then
        # A static library doesn't carry its own dependencies; wolfSSL's build
        # records them in the pkg-config Libs.private line (on macOS this is
        # where -framework CoreFoundation -framework Security ends up).
        _bh_libs="$WOLFSSL_DIR/src/.libs/libwolfssl.a"
        if [ -f "$WOLFSSL_DIR/support/wolfssl.pc" ]; then
          _bh_libs="$_bh_libs $(sed -n 's/^Libs\.private: *//p' "$WOLFSSL_DIR/support/wolfssl.pc")"
        fi
      # (one ls per pattern: ls fails when any of its patterns matches nothing)
      elif ls "$WOLFSSL_DIR"/src/.libs/libwolfssl.so* >/dev/null 2>&1 ||
           ls "$WOLFSSL_DIR"/src/.libs/libwolfssl*.dylib >/dev/null 2>&1; then
        _bh_libs="-L$WOLFSSL_DIR/src/.libs -Wl,-rpath,$WOLFSSL_DIR/src/.libs -lwolfssl"
      fi
    fi
    if [ -z "$_bh_libs" ] && have pkg-config && pkg-config --exists wolfssl 2>/dev/null; then
      _bh_cflags=$(pkg-config --cflags wolfssl); _bh_libs=$(pkg-config --libs --static wolfssl)
    fi
    # macOS: wolfSSL's system-trust support needs these frameworks; harmless if unused
    if [ -n "$_bh_libs" ] && [ "$(uname -s)" = Darwin ]; then
      case " $_bh_libs " in
        *" -framework Security "*) ;;
        *) _bh_libs="$_bh_libs -framework CoreFoundation -framework Security" ;;
      esac
    fi
    if [ -z "$_bh_libs" ]; then
      HELPER_WHY="no built wolfSSL library found (set WOLFSSL_DIR to a built source tree)"; return 1
    fi
    _bh_cflags="$_bh_cflags ${HELPER_CFLAGS:-}"
    _bh_libs="$_bh_libs ${HELPER_LIBS:-} -lm -lpthread"
    echo "$_bh_cc -O2 $_bh_cflags $_bh_src -o $_bh_bin $_bh_libs" > "$_bh_log"
    # shellcheck disable=SC2086
    if ! $_bh_cc -O2 $_bh_cflags "$_bh_src" -o "$_bh_bin" $_bh_libs >>"$_bh_log" 2>&1; then
      HELPER_WHY="helper failed to compile against wolfSSL (see logs/$(basename "$_bh_log"))"
      if grep -qiE 'sdk|sysroot|No such file or directory.*\.h' "$_bh_log" 2>/dev/null; then
        HELPER_WHY="$HELPER_WHY; on macOS with a newer SDK than the OS, try SDKROOT=/path/to/older/MacOSX.sdk"
      fi
      return 1
    fi
    HELPER=$_bh_bin
  fi
  # capability probe
  _bh_p=$OUTDIR/tools/probe; mkdir -p "$_bh_p"
  if ! "$HELPER" genkey 44 "$_bh_p/k.der" "$_bh_p/p.der" >"$_bh_p/genkey.log" 2>&1; then
    HELPER_WHY="helper can't generate ML-DSA keys (wolfSSL built without --enable-mldsa?)"; HELPER=; return 1
  fi
  "$HELPER" mkca 44 "$_bh_p/ca.key" "$_bh_p/ca.der" probe >"$_bh_p/mkca.log" 2>&1
  case $? in
    0) HELPER_CERTGEN=1 ;;
    3) HELPER_CERTGEN_WHY="wolfSSL built without --enable-certgen" ;;
    *) HELPER_CERTGEN_WHY="wolfSSL certificate generation failed (see tools/probe/mkca.log)" ;;
  esac
  # its leaves carry a subjectAltName only when wolfSSL has WOLFSSL_ALT_NAMES
  if [ "$HELPER_CERTGEN" = 1 ] &&
     "$HELPER" mkleaf 44 44 "$_bh_p/ca.key" "$_bh_p/ca.der" localhost server \
       "$_bh_p/leaf.key" "$_bh_p/leaf.der" >"$_bh_p/mkleaf.log" 2>&1 &&
     "$OPENSSL" x509 -inform DER -in "$_bh_p/leaf.der" -noout -ext subjectAltName 2>/dev/null |
       grep -q 'DNS:localhost'; then
    HELPER_SAN=1
  fi
  return 0
}

# ----------------------------------------------------------------------------
# ML-DSA mode: result recording
# ----------------------------------------------------------------------------
ML_N=0
# mutual TLS: the pair's key-exchange group (MLDSA_GROUP, or with --pure-pq a
# fallback), the fallback note added to its checks' detail, and every fallback
ML_GRP=; ML_NOTE=; ML_FB=
ml_rec() { # CATEGORY PROFILE PRODUCER CONSUMER TEST EXPECT RESULT DETAIL
  # fields are unquoted (ml_summary and the exit status read them with awk -F,):
  # free-text fields get ';' for ',' and no newlines
  _mr_t=$(printf '%s' "$5" | tr ',\n' '; ')
  _mr_e=$(printf '%s' "$6" | tr ',\n' '; ')
  _mr_d=$(printf '%s' "$8" | tr ',\n' ';  ')
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$_mr_t" "$_mr_e" "$7" "$_mr_d" >> "$MLCSV"
  case $7 in PASS) _mr_c=$C_GR ;; FAIL) _mr_c=$C_RD ;; *) _mr_c=$C_YL ;; esac
  printf "  %s%-4s%s  %-5s %-${LIBW}s -> %-${LIBW2}s %s\n" "$_mr_c" "$7" "$C_0" "$2" "$3" "$4" "$5"
  if [ -n "$_mr_d" ] && [ "$7" != PASS ]; then printf '        %s\n' "$_mr_d"; fi
}
ml_skip() { # CATEGORY PROFILE PRODUCER CONSUMER TEST REASON
  ml_rec "$1" "$2" "$3" "$4" "$5" - SKIP "$6"
}
# ml_check ok|reject CATEGORY PROFILE PRODUCER CONSUMER TEST command...
#   ok:     PASS when the command succeeds
#   reject: PASS when the command fails (negative test)
ml_check() {
  _mc_e=$1; _mc_cat=$2; _mc_p=$3; _mc_pr=$4; _mc_co=$5; _mc_t=$6; shift 6
  ML_N=$((ML_N + 1))
  _mc_log=$MLLOG/$(printf '%03d' "$ML_N")-$_mc_cat.log
  { echo "# $_mc_t  [$_mc_pr -> $_mc_co, profile $_mc_p, expect $_mc_e]"; echo "# $*"; } > "$_mc_log"
  "$@" >>"$_mc_log" 2>&1; _mc_rc=$?
  if [ "$_mc_e" = ok ]; then
    if [ $_mc_rc -eq 0 ]; then _mc_r=PASS; else _mc_r=FAIL; fi
  else
    if [ $_mc_rc -ne 0 ]; then _mc_r=PASS; else _mc_r=FAIL; fi
  fi
  _mc_d=
  if [ $_mc_r = FAIL ]; then
    if [ "$_mc_e" = ok ]; then
      _mc_d=$(grep -v '^#' "$_mc_log" | grep -iE 'error|fail|invalid|unable|cannot|alert|unsupported|not found' \
                | head -n 1 | cut -c1-140)
    else
      _mc_d="accepted but should have been rejected"
    fi
    _mc_d="${_mc_d:+$_mc_d }(logs/mldsa/$(basename "$_mc_log"))"
  fi
  if [ -n "$ML_NOTE" ]; then _mc_d="${_mc_d:+$_mc_d; }$ML_NOTE"; fi
  ml_rec "$_mc_cat" "$_mc_p" "$_mc_pr" "$_mc_co" "$_mc_t" "$_mc_e" "$_mc_r" "$_mc_d"
  [ $_mc_r = PASS ]
}

pem_wrap() { # LABEL IN.der OUT.pem  (plain base64 armour; no re-encoding)
  { echo "-----BEGIN $1-----"; "$OPENSSL" base64 -e -in "$2"; echo "-----END $1-----"; } > "$3"
}

# ----------------------------------------------------------------------------
# ML-DSA mode: individual checks (each returns 0 on success)
# ----------------------------------------------------------------------------
t_wolf_sign_ossl_verify() { # L KEY_DER PUB_DER
  "$HELPER" sign "$1" "$2" "$MLMSG" "$MLTMP.sig" &&
  "$OPENSSL" pkeyutl -verify -rawin -pubin -keyform DER -inkey "$3" -in "$MLMSG" -sigfile "$MLTMP.sig"
}
t_ossl_sign_wolf_verify() { # L KEY KEYFORM PUB_DER
  "$OPENSSL" pkeyutl -sign -rawin -keyform "$3" -inkey "$2" -in "$MLMSG" -out "$MLTMP.sig" &&
  "$HELPER" verify "$1" "$4" "$MLMSG" "$MLTMP.sig"
}
t_tampered_verify() { # VERIFIER L PUB_DER GOOD_SIG  (fails = tamper detected)
  cp "$4" "$MLTMP.bad" || return 2
  _tv_b=$(od -An -tu1 -j 40 -N 1 "$MLTMP.bad" | tr -d ' ')
  if [ "$_tv_b" = 65 ]; then _tv_ch=B; else _tv_ch=A; fi
  printf '%s' "$_tv_ch" | dd of="$MLTMP.bad" bs=1 seek=40 conv=notrunc 2>/dev/null
  if [ "$1" = wolfssl ]; then
    "$HELPER" verify "$2" "$3" "$MLMSG" "$MLTMP.bad"
  else
    "$OPENSSL" pkeyutl -verify -rawin -pubin -keyform DER -inkey "$3" -in "$MLMSG" -sigfile "$MLTMP.bad"
  fi
}
t_verify_chain() { # VERIFIER CA LEAF PURPOSE
  if [ "$1" = openssl ]; then
    "$OPENSSL" verify -purpose "$4" -CAfile "$2" "$3"
  else
    "$HELPER" verifycert "$2" "$3"
  fi
}
t_tls() { # CLIENT PORT  -> 0 only if the full request/response completed
  # A TLS 1.3 client can finish its handshake before the server rejects its
  # certificate, so require the HTTP response, not just a zero exit code.
  [ -n "$CAP_NEXT" ] && cap_begin "$CAP_NEXT" "$2"
  _tt_out=$(run_client "$1" "$ML_GRP" "$2" brief 2>&1); _tt_rc=$?
  [ -n "$CAP_NEXT" ] && cap_end
  printf '%s\n' "$_tt_out"
  [ "$_tt_rc" -eq 0 ] && printf '%s\n' "$_tt_out" | grep -q "$HTTP_RESPONSE"
}

# mk_chain_openssl / mk_chain_wolfssl DIR CA_ALG LEAF_ALG CA_CN ROLES: a CA and
# a leaf for each of ROLES (srv: CN and DNS localhost + IP 127.0.0.1,
# serverAuth; cli: "pqc-bench client", clientAuth), issued by OpenSSL or the
# wolfSSL helper, as DIR/ca.pem, DIR/<role>.pem and DIR/<role>.key.pem. ALG:
# 44, 65 or 87 (ML-DSA) or ec (ECDSA P-256; both ends, no mixed chains)
mk_chain_openssl() {
  case $2 in ec) _mo_ca="-algorithm EC -pkeyopt ec_paramgen_curve:P-256" ;; *) _mo_ca="-algorithm ML-DSA-$2" ;; esac
  case $3 in ec) _mo_lf="-algorithm EC -pkeyopt ec_paramgen_curve:P-256" ;; *) _mo_lf="-algorithm ML-DSA-$3" ;; esac
  # shellcheck disable=SC2086
  mkdir -p "$1" && write_req_cnf "$1/req.cnf" &&
  "$OPENSSL" genpkey $_mo_ca -out "$1/ca.key.pem" &&
  "$OPENSSL" req -config "$1/req.cnf" -x509 -new -key "$1/ca.key.pem" \
    -subj "/CN=$4" -days 30 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1/ca.pem" || return 1
  for _mo_role in $5; do
    if [ "$_mo_role" = srv ]; then _mo_cn=localhost; _mo_eku=serverAuth
      _mo_san="subjectAltName=DNS:localhost,IP:127.0.0.1"
    else _mo_cn="pqc-bench client"; _mo_eku=clientAuth; _mo_san="subjectAltName=DNS:pqc-bench-client"; fi
    printf '%s\n' "$_mo_san" "basicConstraints=CA:FALSE" "keyUsage=critical,digitalSignature" \
      "extendedKeyUsage=$_mo_eku" > "$1/$_mo_role.ext"
    # shellcheck disable=SC2086
    "$OPENSSL" genpkey $_mo_lf -out "$1/$_mo_role.key.pem" &&
    "$OPENSSL" req -config "$1/req.cnf" -new -key "$1/$_mo_role.key.pem" -subj "/CN=$_mo_cn" \
      -out "$1/$_mo_role.csr" &&
    "$OPENSSL" x509 -req -in "$1/$_mo_role.csr" -CA "$1/ca.pem" -CAkey "$1/ca.key.pem" \
      -CAcreateserial -days 30 -extfile "$1/$_mo_role.ext" -out "$1/$_mo_role.pem" || return 1
    if [ -n "$MLDSA_KEY_FORMAT" ] && [ "$3" != ec ]; then
      "$OPENSSL" pkey -in "$1/$_mo_role.key.pem" -provparam "ml-dsa.output_formats=$MLDSA_KEY_FORMAT" \
        -out "$1/$_mo_role.key.tmp" && mv "$1/$_mo_role.key.tmp" "$1/$_mo_role.key.pem" || return 1
    fi
  done
}

mk_chain_wolfssl() {
  mkdir -p "$1" || return 1
  if [ "$2" = ec ]; then "$HELPER" ecmkca "$1/ca.key.der" "$1/ca.der" "$4" || return 1
  else "$HELPER" mkca "$2" "$1/ca.key.der" "$1/ca.der" "$4" || return 1; fi
  pem_wrap CERTIFICATE "$1/ca.der" "$1/ca.pem" || return 1
  for _mw in $5; do
    if [ "$_mw" = srv ]; then _mw_cn=localhost; _mw_use=server; else _mw_cn="pqc-bench client"; _mw_use=client; fi
    if [ "$3" = ec ]; then
      # (SEC1 key: "EC PRIVATE KEY")
      "$HELPER" ecmkleaf "$1/ca.key.der" "$1/ca.der" "$_mw_cn" "$_mw_use" \
        "$1/$_mw.key.der" "$1/$_mw.der" || return 1
      _mw_kl="EC PRIVATE KEY"
    else
      "$HELPER" mkleaf "$3" "$2" "$1/ca.key.der" "$1/ca.der" "$_mw_cn" "$_mw_use" \
        "$1/$_mw.key.der" "$1/$_mw.der" || return 1
      _mw_kl="PRIVATE KEY"
    fi
    pem_wrap CERTIFICATE "$1/$_mw.der" "$1/$_mw.pem" &&
    pem_wrap "$_mw_kl" "$1/$_mw.key.der" "$1/$_mw.key.pem" || return 1
  done
}

# ----------------------------------------------------------------------------
# ML-DSA mode: test sections
# ----------------------------------------------------------------------------
ml_keys_sigs() { # LEVEL
  _ks_l=$1; _ks_d=$MLDIR/keys/mldsa$_ks_l; mkdir -p "$_ks_d"
  if ! { "$OPENSSL" genpkey -algorithm "ML-DSA-$_ks_l" -out "$_ks_d/o.key.pem" &&
         "$OPENSSL" pkey -in "$_ks_d/o.key.pem" -pubout -outform DER -out "$_ks_d/o.pub.der" &&
         "$OPENSSL" pkeyutl -sign -rawin -inkey "$_ks_d/o.key.pem" -in "$MLMSG" -out "$_ks_d/o.sig"
       } >"$MLLOG/setup-openssl-mldsa$_ks_l.log" 2>&1; then
    ml_rec key "$_ks_l" openssl - "generate key and signature" ok FAIL \
      "OpenSSL can't use ML-DSA-$_ks_l (needs 3.5+; logs/mldsa/setup-openssl-mldsa$_ks_l.log)"
    return
  fi
  if [ -z "$HELPER" ]; then
    ml_skip key "$_ks_l" both both "all key and signature checks" "$HELPER_WHY"
    return
  fi

  for _ks_f in seed-priv seed-only priv-only; do
    if "$OPENSSL" pkey -in "$_ks_d/o.key.pem" -provparam "ml-dsa.output_formats=$_ks_f" \
         -outform DER -out "$_ks_d/o.$_ks_f.der" >/dev/null 2>&1; then
      ml_check ok key "$_ks_l" openssl wolfssl "private key ($_ks_f): decode + sign; OpenSSL verifies" \
        t_wolf_sign_ossl_verify "$_ks_l" "$_ks_d/o.$_ks_f.der" "$_ks_d/o.pub.der"
    else
      ml_skip key "$_ks_l" openssl wolfssl "private key ($_ks_f)" "this OpenSSL can't write the $_ks_f encoding"
    fi
  done
  ml_check ok key "$_ks_l" openssl wolfssl "public key (SPKI) decode" \
    "$HELPER" checkpub "$_ks_l" "$_ks_d/o.pub.der"

  if ! { "$HELPER" genkey "$_ks_l" "$_ks_d/w.key.der" "$_ks_d/w.pub.der" &&
         "$HELPER" sign "$_ks_l" "$_ks_d/w.key.der" "$MLMSG" "$_ks_d/w.sig"
       } >"$MLLOG/setup-wolfssl-mldsa$_ks_l.log" 2>&1; then
    ml_rec key "$_ks_l" wolfssl - "generate key and signature" ok FAIL \
      "wolfSSL key generation failed (logs/mldsa/setup-wolfssl-mldsa$_ks_l.log)"
    return
  fi
  ml_check ok key "$_ks_l" wolfssl openssl "private key decode" \
    "$OPENSSL" pkey -inform DER -in "$_ks_d/w.key.der" -noout
  ml_check ok key "$_ks_l" wolfssl openssl "public key (SPKI) decode" \
    "$OPENSSL" pkey -pubin -inform DER -in "$_ks_d/w.pub.der" -noout

  ml_check ok sig "$_ks_l" openssl wolfssl "OpenSSL signs, wolfSSL verifies" \
    "$HELPER" verify "$_ks_l" "$_ks_d/o.pub.der" "$MLMSG" "$_ks_d/o.sig"
  ml_check ok sig "$_ks_l" wolfssl openssl "wolfSSL signs, OpenSSL verifies" \
    "$OPENSSL" pkeyutl -verify -rawin -pubin -keyform DER -inkey "$_ks_d/w.pub.der" \
      -in "$MLMSG" -sigfile "$_ks_d/w.sig"
  ml_check ok sig "$_ks_l" wolfssl openssl "OpenSSL signs with wolfSSL key; wolfSSL verifies" \
    t_ossl_sign_wolf_verify "$_ks_l" "$_ks_d/w.key.der" DER "$_ks_d/w.pub.der"
  ml_check reject sig "$_ks_l" openssl wolfssl "tampered signature rejected" \
    t_tampered_verify wolfssl "$_ks_l" "$_ks_d/o.pub.der" "$_ks_d/o.sig"
  ml_check reject sig "$_ks_l" wolfssl openssl "tampered signature rejected" \
    t_tampered_verify openssl "$_ks_l" "$_ks_d/w.pub.der" "$_ks_d/w.sig"
}

ptag() { printf '%s\n' "$1" | tr -c 'A-Za-z0-9\n' '_'; }

ml_materials() { # PROFILE
  ml_split "$1"; _mm_t=$(ptag "$1"); _mm_d=$MLDIR/chains/$1; mkdir -p "$_mm_d"
  # untrusted CA for negative tests
  ROGUE_CA=$_mm_d/rogue-ca.pem
  if ! { write_req_cnf "$_mm_d/req.cnf" &&
         "$OPENSSL" genpkey -algorithm "ML-DSA-$ML_CAL" -out "$_mm_d/rogue-ca.key.pem" &&
         "$OPENSSL" req -config "$_mm_d/req.cnf" -x509 -new -key "$_mm_d/rogue-ca.key.pem" \
           -subj "/CN=Untrusted ML-DSA CA" -days 30 -addext "basicConstraints=critical,CA:TRUE" \
           -addext "keyUsage=critical,keyCertSign" -out "$ROGUE_CA"
       } >"$MLLOG/setup-rogue-$_mm_t.log" 2>&1; then
    ROGUE_CA=
  fi
  eval "AV_openssl_$_mm_t=0; AV_wolfssl_$_mm_t=0"
  if ml_check ok certgen "$1" openssl openssl "issue CA + server + client certs" \
       mk_chain_openssl "$_mm_d/openssl" "$ML_CAL" "$ML_LL" "OpenSSL ML-DSA-$ML_CAL CA" "srv cli"; then
    eval "AV_openssl_$_mm_t=1"
  fi
  if [ -z "$HELPER" ]; then
    ml_skip certgen "$1" wolfssl wolfssl "issue CA + server + client certs" "$HELPER_WHY"
  elif [ "$HELPER_CERTGEN" != 1 ]; then
    ml_skip certgen "$1" wolfssl wolfssl "issue CA + server + client certs" "$HELPER_CERTGEN_WHY"
  elif ml_check ok certgen "$1" wolfssl wolfssl "issue CA + server + client certs" \
         mk_chain_wolfssl "$_mm_d/wolfssl" "$ML_CAL" "$ML_LL" "wolfSSL ML-DSA-$ML_CAL CA" "srv cli"; then
    eval "AV_wolfssl_$_mm_t=1"
  fi
}

ml_certs() { # PROFILE
  _mc2_t=$(ptag "$1"); _mc2_d=$MLDIR/chains/$1
  for _mc2_x in openssl wolfssl; do
    eval "_mc2_av=\$AV_${_mc2_x}_$_mc2_t"
    [ "$_mc2_av" = 1 ] || continue
    for _mc2_y in openssl wolfssl; do
      if [ "$_mc2_y" = wolfssl ] && [ -z "$HELPER" ]; then
        ml_skip cert "$1" "$_mc2_x" wolfssl "verify chains" "$HELPER_WHY"; continue
      fi
      ml_check ok cert "$1" "$_mc2_x" "$_mc2_y" "verify server chain" \
        t_verify_chain "$_mc2_y" "$_mc2_d/$_mc2_x/ca.pem" "$_mc2_d/$_mc2_x/srv.pem" sslserver
      ml_check ok cert "$1" "$_mc2_x" "$_mc2_y" "verify client chain" \
        t_verify_chain "$_mc2_y" "$_mc2_d/$_mc2_x/ca.pem" "$_mc2_d/$_mc2_x/cli.pem" sslclient
      if [ -n "$ROGUE_CA" ]; then
        ml_check reject cert "$1" "$_mc2_x" "$_mc2_y" "server cert rejected under untrusted CA" \
          t_verify_chain "$_mc2_y" "$ROGUE_CA" "$_mc2_d/$_mc2_x/srv.pem" sslserver
      fi
    done
  done
}

ml_time() { # PROFILE PRODUCER CLIENT SERVER PORT LABEL
  _mt_i=0
  while [ $_mt_i -lt "$WARMUP" ]; do
    ensure_server "$4" "$ML_GRP" "$6"; run_client "$3" "$ML_GRP" "$5" >/dev/null 2>&1 && SRV_SERVED=$4
    _mt_i=$((_mt_i + 1))
  done
  _mt_fails=0; _mt_i=1
  while [ $_mt_i -le "$MLDSA_ITERATIONS" ]; do
    if ensure_server "$4" "$ML_GRP" "$6"; then
      _mt_t0=$(now_ns)
      run_client "$3" "$ML_GRP" "$5" >/dev/null 2>&1; _mt_rc=$?
      _mt_t1=$(now_ns)
      if [ $_mt_rc -eq 0 ]; then
        SRV_SERVED=$4
        printf '%s,%s,%s,%s,%d,%s,%s\n' "$1" "$2" "$3" "$4" "$_mt_i" "$(elapsed_ms "$_mt_t0" "$_mt_t1")" "$ML_GRP" >> "$MLRAW"
      else _mt_fails=$((_mt_fails + 1)); fi
    else _mt_fails=$((_mt_fails + 1)); fi
    _mt_i=$((_mt_i + 1))
  done
  printf '%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$4" "$_mt_fails" "$ML_GRP" >> "$MLMETA"
  _mt_med=$(awk -F, -v p="$1" -v x="$2" -v c="$3" -v s="$4" \
              'NR>1 && $1==p && $2==x && $3==c && $4==s {print $6}' "$MLRAW" | median_of)
  printf '        timed %s handshakes: median %s ms%s\n' "$MLDSA_ITERATIONS" "$_mt_med" \
    "$( [ "$_mt_fails" -gt 0 ] && printf ' (%s failed)' "$_mt_fails" )"
}

ml_tls() { # PROFILE
  _tl_t=$(ptag "$1"); _tl_d=$MLDIR/chains/$1
  for _tl_x in openssl wolfssl; do
    eval "_tl_av=\$AV_${_tl_x}_$_tl_t"
    if [ "$_tl_av" != 1 ]; then
      if [ "$_tl_x" = wolfssl ] && [ -z "$HELPER" ]; then _tl_why=$HELPER_WHY
      elif [ "$_tl_x" = wolfssl ] && [ "$HELPER_CERTGEN" != 1 ]; then _tl_why=$HELPER_CERTGEN_WHY
      else _tl_why="the $_tl_x-issued chain could not be created (see certgen above)"; fi
      ml_skip tls "$1" "$_tl_x" all "mutual TLS" "$_tl_why"; continue
    fi
    _tl_cd=$_tl_d/$_tl_x; _tl_label=mldsa-$_tl_t-$_tl_x
    SRV_CERT=$_tl_cd/srv.pem; SRV_KEY=$_tl_cd/srv.key.pem; SRV_CA=$_tl_cd/ca.pem
    alloc_ports
    for _tl_srv in $ML_SRV_LIBS; do
      # (--pure-pq) a server lacking MLDSA_GROUP starts when a pair's fallback needs it
      [ -n "$("${_tl_srv}_srv_skip" "$MLDSA_GROUP")" ] && continue
      start_server "$_tl_srv" "$MLDSA_GROUP" "$_tl_label"
    done
    for _tl_srv in $ML_SRV_LIBS; do
      eval "_tl_port=\$SPORT_$_tl_srv"
      for _tl_cli in $ML_TLS_CLIS; do
        _tl_dir="$_tl_cli->$_tl_srv"
        # this pair's group, and its server's label (own logs for a fallback)
        ML_GRP=$MLDSA_GROUP; ML_NOTE=; _tl_sl=$_tl_label
        if [ "$PURE_PQ" = 1 ]; then
          if ! pq_pick "$_tl_cli" "$_tl_srv" "$MLDSA_GROUP"; then
            ml_skip tls "$1" "$_tl_x" "$_tl_dir" "mutual TLS" "no usable key-exchange group: $PQ_WHY"; continue
          fi
          if [ "$PQ_GROUP" != "$MLDSA_GROUP" ]; then
            ML_GRP=$PQ_GROUP; _tl_sl=$_tl_label-$PQ_GROUP
            ML_NOTE="pure-PQ fallback to $(group_kind "$ML_GRP") $ML_GRP ($PQ_WHY)"
            ML_FB="$ML_FB
  $_tl_dir: $(group_kind "$ML_GRP") $ML_GRP ($PQ_WHY)"
          fi
        fi
        # (--pure-pq: pq_pick already checked) a pair whose libraries can't use
        # this group or chain, e.g. a rustls provider without ML-DSA
        if [ "$PURE_PQ" != 1 ]; then
          _tl_why=$(pair_skip "$_tl_cli" "$_tl_srv" "$ML_GRP")
          if [ -n "$_tl_why" ]; then ml_skip tls "$1" "$_tl_x" "$_tl_dir" "mutual TLS" "$_tl_why"; continue; fi
        fi
        # a client that ignores the CN can't verify a leaf without a subjectAltName
        eval "_tl_so=\${LIBSANONLY_$_tl_cli:-0}"
        if [ "$_tl_x" = wolfssl ] && [ "$HELPER_SAN" != 1 ] && [ "$_tl_so" = 1 ]; then
          ml_skip tls "$1" "$_tl_x" "$_tl_dir" "mutual TLS" "the wolfSSL-issued server certificate has no subjectAltName and the $(lib_name "$_tl_cli") client needs one (wolfSSL built without CPPFLAGS=-DWOLFSSL_ALT_NAMES; ./setup.sh wolfssl rebuilds it)"
          continue
        fi
        if ! ensure_server "$_tl_srv" "$ML_GRP" "$_tl_sl"; then
          ml_rec tls "$1" "$_tl_x" "$_tl_dir" "mutual TLS" ok FAIL \
            "$_tl_srv server failed to start with this chain (logs/server-$_tl_srv-$_tl_sl.log)${ML_NOTE:+; $ML_NOTE}"
          continue
        fi
        CLI_CA=$_tl_cd/ca.pem; CLI_CERT=$_tl_cd/cli.pem; CLI_KEY=$_tl_cd/cli.key.pem
        CAP_LABEL=$_tl_sl; _tl_cap=mldsa/$1-$_tl_x-chain/$_tl_cli-to-$_tl_srv
        [ "$CAPTURE" = 1 ] && CAP_NEXT=$_tl_cap-mutual
        if ml_check ok tls "$1" "$_tl_x" "$_tl_dir" "mutual TLS" t_tls "$_tl_cli" "$_tl_port"; then
          CAP_NEXT=
          [ -n "$ML_NOTE" ] && printf '        note: %s\n' "$ML_NOTE"
          [ "$MLDSA_ITERATIONS" -gt 0 ] && ml_time "$1" "$_tl_x" "$_tl_cli" "$_tl_srv" "$_tl_port" "$_tl_sl"
          [ "$INPROC" = 1 ] && [ "$MLDSA_ITERATIONS" -gt 0 ] &&
            inproc_pair mldsa "$1,$_tl_x" "$_tl_cli" "$_tl_srv" "$_tl_port" "$ML_GRP" "$_tl_sl" "$MLDSA_ITERATIONS"
        fi
        CLI_CERT=; CLI_KEY=
        [ "$CAPTURE" = 1 ] && CAP_NEXT=$_tl_cap-nocert
        if ensure_server "$_tl_srv" "$ML_GRP" "$_tl_sl"; then
          ml_check reject tls "$1" "$_tl_x" "$_tl_dir" "client without certificate refused" \
            t_tls "$_tl_cli" "$_tl_port"
        fi
        if [ -n "$ROGUE_CA" ] && ensure_server "$_tl_srv" "$ML_GRP" "$_tl_sl"; then
          CLI_CA=$ROGUE_CA; CLI_CERT=$_tl_cd/cli.pem; CLI_KEY=$_tl_cd/cli.key.pem
          [ "$CAPTURE" = 1 ] && CAP_NEXT=$_tl_cap-untrusted
          ml_check reject tls "$1" "$_tl_x" "$_tl_dir" "untrusted server chain refused" \
            t_tls "$_tl_cli" "$_tl_port"
        fi
        CAP_NEXT=
      done
    done
    stop_servers
  done
  ML_NOTE=
}

ml_summary() {
  hdr "ML-DSA interop summary"
  {
    echo "category,pass,fail,skip"
    awk -F, 'NR>1 { k[$1]=1; n[$1","$7]++ }
             END { split("key sig certgen cert tls", o, " ")
                   for (i = 1; i <= 5; i++) if (o[i] in k)
                     printf "%s,%d,%d,%d\n", o[i], n[o[i]",PASS"], n[o[i]",FAIL"], n[o[i]",SKIP"] }' "$MLCSV"
  } | print_table
  _ms_tot=$(awk -F, 'NR>1{t++; if($7=="FAIL")f++; if($7=="SKIP")s++} END{printf "%d checks, %d failed, %d skipped", t, f, s}' "$MLCSV")
  printf '\n%s\n' "$_ms_tot"
  _ms_fail=$(awk -F, 'NR>1 && $7=="FAIL" {printf "  %s %s %s->%s: %s  %s\n", $1, $2, $3, $4, $5, $8}' "$MLCSV")
  if [ -n "$_ms_fail" ]; then printf '\nFailures:\n%s\n' "$_ms_fail"; fi
  _ms_skip=$(awk -F, 'NR>1 && $7=="SKIP" {print "  " $8}' "$MLCSV" | sort -u)
  if [ -n "$_ms_skip" ]; then printf '\nSkipped because:\n%s\n' "$_ms_skip"; fi
  if [ -n "$ML_FB" ]; then
    printf '\nPure-PQ fallbacks (mutual-TLS pairs that could not use %s):\n%s\n' "$MLDSA_GROUP" \
      "$(printf '%s\n' "$ML_FB" | sed '/^$/d' | sort -u)"
  fi

  if [ -s "$MLMETA" ]; then
    MLSUM=$OUTDIR/mldsa_handshakes_summary.csv
    echo "profile,producer,client,server,n,min_ms,median_ms,mean_ms,p95_ms,max_ms,adj_median_ms,failed,group" > "$MLSUM"
    while IFS=, read -r _ms_p _ms_x _ms_c _ms_s _ms_f _ms_g; do
      eval "_ms_base=\$STARTUP_$_ms_c"
      _ms_stats=$(awk -F, -v p="$_ms_p" -v x="$_ms_x" -v c="$_ms_c" -v s="$_ms_s" \
                    'NR>1 && $1==p && $2==x && $3==c && $4==s {print $6}' "$MLRAW" | stats_line "$_ms_base")
      printf '%s,%s,%s,%s,%s,%s,%s\n' "$_ms_p" "$_ms_x" "$_ms_c" "$_ms_s" "$_ms_stats" "$_ms_f" "$_ms_g" >> "$MLSUM"
    done < "$MLMETA"
    hdr "Handshake summary, mutual TLS with ML-DSA ($MLDSA_GROUP) (ms)"
    print_table < "$MLSUM"
    printf '\nprofile = CA-leaf ML-DSA levels; producer = library that issued the chain;\n'
    printf 'group = key exchange (differs from %s only after a --pure-pq fallback).\n' "$MLDSA_GROUP"
    printf 'adj_median_ms = median minus client process-startup baseline.\n'
  fi
  if [ "$INPROC" = 1 ] && [ -s "$MLINMETA" ]; then
    MLINSUM=$OUTDIR/mldsa_handshakes_inproc_summary.csv
    inproc_summary "$MLINRAW" "$MLINMETA" "$MLINSUM" profile,producer group
    hdr "Handshake summary, mutual TLS with ML-DSA, in-process hsloop clients (ms)"
    cut -d, -f1-5,7,9,12,15,16,17 "$MLINSUM" | print_table
    printf '\nmedian_ms = whole handshake sample, all in one client process;\n'
    printf 'init_ms = library start-up and client setup (certificate and key loaded once), once per run.\n'
  fi
}

run_mldsa() {
  hdr "ML-DSA interoperability"
  MLDIR=$OUTDIR/mldsa; MLLOG=$LOGDIR/mldsa; mkdir -p "$MLDIR" "$MLLOG"
  MLCSV=$OUTDIR/mldsa_interop.csv
  echo "category,profile,producer,consumer,test,expect,result,detail" > "$MLCSV"
  MLRAW=$OUTDIR/mldsa_handshakes_raw.csv
  echo "profile,producer,client,server,iteration,ms,group" > "$MLRAW"
  MLMETA=$LOGDIR/mldsa-pairs.csv; : > "$MLMETA"
  MLINRAW=$OUTDIR/mldsa_handshakes_inproc_raw.csv; MLINMETA=$LOGDIR/mldsa-inproc-pairs.csv
  if [ "$INPROC" = 1 ]; then echo "profile,producer,client,server,$INPROC_COLS" > "$MLINRAW"; : > "$MLINMETA"; fi
  MLMSG=$MLDIR/message.txt; MLTMP=$MLDIR/tmp
  printf 'pqc-bench ML-DSA interop test message\n' > "$MLMSG"

  # with --pure-pq every pair takes part: pq_pick gives it a group (ml_tls)
  # CERTK and the mutual-TLS clients (ML_TLS_CLIS) are set per profile below
  CERTK=; ML_SRV_LIBS=$LIBS; ML_CLI_LIBS=$LIBS; ML_TLS_CLIS=; ML_LIB_SKIPS=; ML_FB=
  if [ "$PURE_PQ" != 1 ]; then
    case $(wolf_args "$MLDSA_GROUP") in
      UNKNOWN|SKIP) die "MLDSA_GROUP=$MLDSA_GROUP is not a group the wolfSSL client can pin (see GROUP TABLE in libs/wolfssl.sh)" ;;
    esac
    # (the wolfSSL FIPS build has no X25519MLKEM768)
    wolfssl_has_group "$MLDSA_GROUP" ||
      die "MLDSA_GROUP=$MLDSA_GROUP: this wolfSSL build lacks it (use another group, or --pure-pq)"
  fi

  # a library whose server can't use MLDSA_GROUP sits out the mutual-TLS pairs
  # (with --pure-pq a pair gets a fallback group instead); its client also
  # needs a way to pin MLDSA_GROUP with each profile's ML-DSA levels, checked
  # per profile below
  if [ "$PURE_PQ" != 1 ]; then
    for _rm_x in $LIBS; do
      _rm_why=$("${_rm_x}_srv_skip" "$MLDSA_GROUP")
      [ -n "$_rm_why" ] || continue
      ML_SRV_LIBS=$(echo " $ML_SRV_LIBS " | sed "s/ $_rm_x / /; s/^ //; s/ \$//")
      ML_CLI_LIBS=$(echo " $ML_CLI_LIBS " | sed "s/ $_rm_x / /; s/^ //; s/ \$//")
      lib_has "$_rm_x" mldsa_hint && _rm_why="$_rm_why ($("${_rm_x}_mldsa_hint"))"
      ML_LIB_SKIPS="$ML_LIB_SKIPS$_rm_x pairs|$_rm_why
"
    done
  fi

  if build_helper; then
    info "wolfSSL helper: $HELPER"
    [ "$HELPER_CERTGEN" = 1 ] || warn "wolfSSL-issued certificates unavailable: $HELPER_CERTGEN_WHY"
  else
    warn "wolfSSL helper unavailable: $HELPER_WHY"
    warn "  wolfSSL-side key, signature and certificate checks will be skipped"
  fi

  _rm_levels=
  for _rm_l in 44 65 87; do
    for _rm_p in $MLDSA_PROFILES; do
      ml_split "$_rm_p"
      if [ "$ML_CAL" = "$_rm_l" ] || [ "$ML_LL" = "$_rm_l" ]; then _rm_levels="$_rm_levels $_rm_l"; break; fi
    done
  done

  sub "Keys and signatures (ML-DSA-${_rm_levels# })"
  printf "  %-4s  %-5s %-${LIBW}s    %-${LIBW2}s %s\n" result level producer consumer test
  for _rm_l in $_rm_levels; do ml_keys_sigs "$_rm_l"; done

  sub "Certificates (profiles: $MLDSA_PROFILES)"
  for _rm_p in $MLDSA_PROFILES; do ml_materials "$_rm_p"; ml_certs "$_rm_p"; done

  if [ "$PURE_PQ" = 1 ]; then
    sub "Mutual TLS, key exchange $MLDSA_GROUP where the pair supports it (--pure-pq)"
  else
    sub "Mutual TLS, key exchange $MLDSA_GROUP"
  fi
  measure_startups
  while IFS='|' read -r _rm_who _rm_why; do
    [ -n "$_rm_who" ] && ml_skip tls all - "$_rm_who" "mutual TLS" "$_rm_why"
  done <<EOF
$ML_LIB_SKIPS
EOF
  for _rm_p in $MLDSA_PROFILES; do
    ml_split "$_rm_p"
    if [ "$ML_CAL" = "$ML_LL" ]; then CERTK=mldsa$ML_CAL; else CERTK=mldsa$ML_CAL-$ML_LL; fi
    ML_TLS_CLIS=
    for _rm_x in $ML_CLI_LIBS; do
      _rm_why=
      # (--pure-pq instead gives such a pair a fallback group: pq_pick)
      if [ "$PURE_PQ" != 1 ]; then
        if lib_has "$_rm_x" mldsa_cli_skip; then _rm_why=$("${_rm_x}_mldsa_cli_skip" "$MLDSA_GROUP")
        else _rm_why=$("${_rm_x}_cli_skip" "$MLDSA_GROUP"); fi
      fi
      if [ -n "$_rm_why" ]; then
        ml_skip tls "$_rm_p" all "$_rm_x client" "mutual TLS" "$_rm_why"
      else
        ML_TLS_CLIS="${ML_TLS_CLIS:+$ML_TLS_CLIS }$_rm_x"
      fi
    done
    # rogue CA for this profile (created in ml_materials)
    ROGUE_CA=$MLDIR/chains/$_rm_p/rogue-ca.pem; [ -f "$ROGUE_CA" ] || ROGUE_CA=
    ml_tls "$_rm_p"
  done

  ml_summary
}

# ----------------------------------------------------------------------------
# VERSIONS mode: TLS version negotiation, downgrade and HelloRetryRequest
#   Each scenario fixes what each side allows (TLS version, key-exchange
#   groups, certificate) and runs in every client -> server direction.
#   The first handshake is checked against the expected outcome; then the
#   case is timed (full handshakes, or time-to-refusal for refused cases).
# ----------------------------------------------------------------------------
VS_ALL="base13 neg13 neg13-both base12 down12-server down12-client
refuse-13v12 refuse-12v13 hybrid13 hybrid-down12 hybrid-hrr
pq13 pq-down12 pq-vs-classical mldsa13 mldsa-down12"

# vs_scenario NAME -> VS_CV VS_SV (1.2|1.3|any), VS_CG (classical|hybrid|pq),
#   VS_SG (any|classical), VS_CERTK (ec|mldsa), VS_EXP (the expected outcome:
#   refuse, or VERSION/KIND), VS_DESC. A library whose client behaves
#   differently adjusts VS_EXPECT / VS_NOTE in its <id>_vs_expect.
vs_scenario() {
  case $1 in
    base13)          set -- 1.3 1.3 classical classical ec "1.3/classical" \
                       "reference: TLS 1.3 both sides, X25519" ;;
    neg13)           set -- any 1.3 classical classical ec "1.3/classical" \
                       "client negotiates 1.2-1.3, server 1.3 only" ;;
    neg13-both)      set -- any any classical classical ec "1.3/classical" \
                       "both sides negotiate 1.2-1.3" ;;
    base12)          set -- 1.2 1.2 classical classical ec "1.2/classical" \
                       "reference: TLS 1.2 both sides, X25519" ;;
    down12-server)   set -- any 1.2 classical classical ec "1.2/classical" \
                       "downgrade: client 1.2-1.3, server caps at 1.2" ;;
    down12-client)   set -- 1.2 any classical classical ec "1.2/classical" \
                       "downgrade: client caps at 1.2, server 1.2-1.3" ;;
    refuse-13v12)    set -- 1.3 1.2 classical classical ec refuse \
                       "no common version: client 1.3 only, server 1.2 only" ;;
    refuse-12v13)    set -- 1.2 1.3 classical classical ec refuse \
                       "no common version: client 1.2 only, server 1.3 only" ;;
    hybrid13)        set -- any any hybrid any ec "1.3/hybrid" \
                       "reference: hybrid X25519MLKEM768 on TLS 1.3" ;;
    hybrid-down12)   set -- any 1.2 hybrid any ec "1.2/classical" \
                       "hybrid client meets TLS 1.2 server (PQ lost)" ;;
    hybrid-hrr)      set -- any 1.3 hybrid classical ec "1.3/classical" \
                       "hybrid client meets classical-only TLS 1.3 server (HRR, PQ lost)" ;;
    pq13)            set -- any any pq any ec "1.3/PQ" \
                       "reference: ML-KEM-1024 client on TLS 1.3" ;;
    pq-down12)       set -- any 1.2 pq any ec refuse \
                       "ML-KEM-only client meets TLS 1.2 server" ;;
    pq-vs-classical) set -- any 1.3 pq classical ec refuse \
                       "ML-KEM-only client meets classical-only TLS 1.3 server" ;;
    mldsa13)         set -- any 1.3 hybrid any mldsa "1.3/hybrid" \
                       "reference: ML-DSA-65 server certificate on TLS 1.3" ;;
    mldsa-down12)    set -- any 1.2 hybrid any mldsa refuse \
                       "ML-DSA-65 server certificate, server caps at 1.2" ;;
    *) return 1 ;;
  esac
  VS_CV=$1; VS_SV=$2; VS_CG=$3; VS_SG=$4; VS_CERTK=$5; VS_EXP=$6; VS_DESC=$7
}
# the one key share the OpenSSL and wolfSSL clients send first, in every setting
vs_keyshare() { case $1 in classical) echo X25519 ;; hybrid) echo X25519MLKEM768 ;; pq) echo MLKEM1024 ;; esac; }

vs_norm_group() {
  _vg=$(printf '%s' "$1" | sed 's/,.*//' | tr '[:lower:]' '[:upper:]' | tr -d ' ')
  case $_vg in
    ECDH) _vg=$(printf '%s' "$1" | awk -F', *' '{print $2}' | tr '[:lower:]' '[:upper:]') ;;
  esac
  case $_vg in
    X25519)                                echo X25519 ;;
    PRIME256V1|SECP256R1|P-256)            echo P-256 ;;
    SECP384R1|P-384)                       echo P-384 ;;
    SECP521R1|P-521)                       echo P-521 ;;
    X25519MLKEM768|X25519_ML_KEM_768)      echo X25519MLKEM768 ;;
    SECP256R1MLKEM768|P256_ML_KEM_768)     echo SecP256r1MLKEM768 ;;
    SECP384R1MLKEM1024|P384_ML_KEM_1024)   echo SecP384r1MLKEM1024 ;;
    MLKEM512|ML_KEM_512)                   echo MLKEM512 ;;
    MLKEM768|ML_KEM_768)                   echo MLKEM768 ;;
    MLKEM1024|ML_KEM_1024)                 echo MLKEM1024 ;;
    '')                                    echo "" ;;
    *)                                     echo "$_vg" ;;
  esac
}

vs_make_certs() { # DIR
  mkdir -p "$1" && write_req_cnf "$1/req.cnf" || return 1
  for _vk in ec mldsa; do
    if [ $_vk = ec ]; then _va='-algorithm EC -pkeyopt ec_paramgen_curve:P-256'; else _va='-algorithm ML-DSA-65'; fi
    printf '%s\n' "subjectAltName=DNS:localhost,IP:127.0.0.1" "basicConstraints=CA:FALSE" \
      "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" > "$1/srv.ext"
    # shellcheck disable=SC2086
    "$OPENSSL" genpkey $_va -out "$1/$_vk-ca.key" &&
    "$OPENSSL" req -config "$1/req.cnf" -x509 -new -key "$1/$_vk-ca.key" -subj "/CN=pqc-bench $_vk CA" \
      -days 30 -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
      -out "$1/$_vk-ca.pem" &&
    "$OPENSSL" genpkey $_va -out "$1/$_vk-srv.key" &&
    "$OPENSSL" req -config "$1/req.cnf" -new -key "$1/$_vk-srv.key" -subj "/CN=localhost" -out "$1/$_vk-srv.csr" &&
    "$OPENSSL" x509 -req -in "$1/$_vk-srv.csr" -CA "$1/$_vk-ca.pem" -CAkey "$1/$_vk-ca.key" \
      -CAcreateserial -days 30 -extfile "$1/srv.ext" -out "$1/$_vk-srv.pem" || return 1
  done
}

vs_start_server() { # IMPL LABEL
  _vs_impl=$1; _vs_label=$2
  eval "_vs_port=\$SPORT_$_vs_impl"
  _vs_log=$LOGDIR/server-$_vs_impl-$_vs_label.log
  if [ -n "$REMOTE" ]; then
    remote_put "$VS_SCERT"; remote_put "$VS_SKEY"
    remote_rel "$VS_SCERT"; _vs_c=$RREL; remote_rel "$VS_SKEY"
    remote_server "$_vs_impl" "" "$_vs_label" "vstart $_vs_impl $_vs_label $_vs_port $CAPTURE $VS_SV $VS_SG $_vs_c $RREL"
    return
  fi
  "${_vs_impl}_vs_server" "$_vs_port" "$_vs_log" "$(srv_keys "$_vs_impl" "$_vs_label")"
  eval "SPID_$_vs_impl=\$!"
  if ! wait_listen "$_vs_port"; then
    eval "START_FAILED_$_vs_impl=\$_vs_label"
    warn "$_vs_impl server didn't start for $_vs_label (see $_vs_log)"
    return 1
  fi
  if lib_has "$_vs_impl" ready; then "${_vs_impl}_ready"; fi
  return 0
}
vs_ensure() { # IMPL LABEL
  eval "_ve_failed=\$START_FAILED_$1"
  [ "$_ve_failed" = "$2" ] && return 1
  eval "_ve_pid=\$SPID_$1; _ve_port=\$SPORT_$1"
  ns_settle "$1"
  if srv_up "$1" "$_ve_pid" "$_ve_port"; then
    SRV_SERVED=; return 0
  fi
  SRV_SERVED=
  stop_server "$1"
  vs_start_server "$1" "$2"
}

vs_client() { # IMPL PORT [brief]
  _vc_impl=$1; shift
  "${_vc_impl}_vs_client" "$@"
}

# OpenSSL-style client output: s_client and the wolfSSL example client
vs_parse_default() { # LOG
  VS_VER=$(sed -n -e 's/^Protocol version: *TLSv//p' -e 's/^SSL version is TLSv//p' "$1" | head -n 1)
  VS_RAWGRP=$(sed -n -e 's/^Negotiated TLS1\.3 group: *//p' -e 's/^Peer Temp Key: *//p' \
            -e 's/^Server Temp Key: *//p' -e 's/^SSL curve name is *//p' "$1" | head -n 1)
}
# vs_parse LOG CLIENT -> VS_OK (1/0) VS_VER (1.2/1.3/"") VS_GRP VS_KIND, and
#   VS_HRRSEEN (yes/no) for clients that report a HelloRetryRequest themselves
vs_parse() {
  if grep -q "$HTTP_RESPONSE" "$1"; then VS_OK=1; else VS_OK=0; fi
  VS_HRRSEEN=; VS_VER=; VS_RAWGRP=
  if lib_has "$2" vs_parse; then "$2_vs_parse" "$1"; else vs_parse_default "$1"; fi
  VS_GRP=$(vs_norm_group "$VS_RAWGRP")
  VS_KIND=$(group_kind "$VS_GRP")
  [ "$VS_OK" = 1 ] || { VS_VER=; VS_GRP=; VS_KIND=; }
}

# handshake round trips (TCP connect and the request/response are the same for
# every case): TLS 1.3 = 1, +1 after a HelloRetryRequest; TLS 1.2 full = 2;
# a refusal = 1 (ClientHello, then an alert)
vs_rtts() { # OUTCOME VER HRR
  if [ "$1" != ok ]; then echo 1
  elif [ "$2" = 1.2 ]; then echo 2
  elif [ "$3" = yes ]; then echo 2
  else echo 1; fi
}
vs_rec() { # SCEN CLIENT SERVER EXPECT OUTCOME VER GROUP HRR PQLOST RESULT DETAIL
  _vr_d=$(printf '%s' "${11}" | tr ',\n' ';  ')
  _vr_rtt=$(vs_rtts "$5" "$6" "$8"); [ "$5" = - ] && _vr_rtt=
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$1" "$2" "$3" "$VS_CV" "$VS_SV" \
    "$VS_CG" "$VS_SG" "$VS_CERTK" "$4" "$5" "$6" "$7" "$8" "$9" "$_vr_rtt" "${10}" "$_vr_d" >> "$VSCSV"
  case ${10} in PASS) _vr_c=$C_GR ;; FAIL) _vr_c=$C_RD ;; *) _vr_c=$C_YL ;; esac
  _vr_got=$5; [ "$5" = ok ] && _vr_got="TLS $6 $7"
  _vr_flags=
  [ "$8" = yes ] && _vr_flags="$_vr_flags HRR"
  [ "$9" = yes ] && _vr_flags="$_vr_flags PQ-lost"
  [ -n "$_vr_rtt" ] && _vr_flags="$_vr_flags  [$_vr_rtt RTT]"
  printf "  %s%-4s%s  %-${LIBW}s -> %-${LIBW}s %-27s%s\n" "$_vr_c" "${10}" "$C_0" "$2" "$3" "$_vr_got" "$_vr_flags"
  if [ -n "$_vr_d" ] && [ "${10}" != PASS ]; then printf '        %s\n' "$_vr_d"; fi
}

# vs_time SCEN CLIENT SERVER PORT LABEL OUTCOME KEEPS. KEEPS=1: the server process
# outlived the checked refusal (s_server, s2nd; wolfSSL's example server exits),
# so a refused run leaves it up like a successful one and the next check can
# skip the port probe: every sample then follows the previous run directly.
vs_time() {
  _vt_i=0
  while [ $_vt_i -lt "$WARMUP" ]; do
    vs_ensure "$3" "$5"
    if vs_client "$2" "$4" >/dev/null 2>&1 || [ "$7" = 1 ]; then SRV_SERVED=$3; fi
    _vt_i=$((_vt_i + 1))
  done
  _vt_f=0; _vt_i=1
  while [ $_vt_i -le "$VERSIONS_ITERATIONS" ]; do
    if vs_ensure "$3" "$5"; then
      _vt_t0=$(now_ns)
      vs_client "$2" "$4" >/dev/null 2>&1; _vt_rc=$?
      _vt_t1=$(now_ns)
      if [ $_vt_rc -eq 0 ] || [ "$7" = 1 ]; then SRV_SERVED=$3; fi
      # keep only runs that ended the same way as the checked handshake
      if { [ "$6" = ok ] && [ $_vt_rc -eq 0 ]; } || { [ "$6" = refused ] && [ $_vt_rc -ne 0 ]; }; then
        printf '%s,%s,%s,%s,%d,%s\n' "$1" "$2" "$3" "$6" "$_vt_i" "$(elapsed_ms "$_vt_t0" "$_vt_t1")" >> "$VSRAW"
      else _vt_f=$((_vt_f + 1)); fi
    else _vt_f=$((_vt_f + 1)); fi
    _vt_i=$((_vt_i + 1))
  done
  _vt_med=$(awk -F, -v s="$1" -v c="$2" -v v="$3" 'NR>1 && $1==s && $2==c && $3==v {print $6}' "$VSRAW" | median_of)
  _vt_what="handshake"; [ "$6" = refused ] && _vt_what="time to refusal"
  printf '        %s: median %s ms over %s runs%s\n' "$_vt_what" "$_vt_med" "$VERSIONS_ITERATIONS" \
    "$( [ "$_vt_f" -gt 0 ] && printf ' (%s ended differently)' "$_vt_f" )"
}

run_versions() {
  hdr "TLS version negotiation and downgrade"
  VSDIR=$OUTDIR/versions; VSLOG=$LOGDIR/versions; mkdir -p "$VSDIR" "$VSLOG"
  VSCSV=$OUTDIR/versions_results.csv
  echo "scenario,client,server,client_version,server_version,client_groups,server_groups,cert,expected,outcome,version,group,hrr,pq_lost,handshake_rtts,result,detail" > "$VSCSV"
  VSRAW=$OUTDIR/versions_handshakes_raw.csv
  echo "scenario,client,server,outcome,iteration,ms" > "$VSRAW"
  vs_make_certs "$VSDIR/certs" >"$VSLOG/certgen.log" 2>&1 \
    || die "certificate generation failed (see $VSLOG/certgen.log)"
  measure_startups
  info "legend: expected outcome per case; HRR = HelloRetryRequest (reported by s2nc; inferred for the other clients: negotiated group != the client's first key share); PQ-lost = client offered post-quantum but got classical"
  if [ "$PURE_PQ" = 1 ]; then
    info "--pure-pq doesn't change this mode: each scenario sets its own groups (pq13, pq-down12 and pq-vs-classical use ML-KEM-1024-only clients)"
  fi

  for _rv_s in $VERSIONS_SCENARIOS; do
    vs_scenario "$_rv_s" || { warn "unknown scenario '$_rv_s'; skipping"; continue; }
    VS_SCERT=$VSDIR/certs/$VS_CERTK-srv.pem; VS_SKEY=$VSDIR/certs/$VS_CERTK-srv.key
    VS_CA=$VSDIR/certs/$VS_CERTK-ca.pem
    sub "$_rv_s: $VS_DESC"
    printf '        client %s (%s) | server %s (%s) | %s cert\n' "$VS_CV" "$VS_CG" "$VS_SV" "$VS_SG" "$VS_CERTK"
    _rv_label=versions-$_rv_s
    alloc_ports
    for _rv_l in $LIBS; do eval "START_FAILED_$_rv_l="; done
    # a server that can't play this scenario as designed isn't started (its pairs are SKIPs)
    for _rv_l in $LIBS; do
      lib_has "$_rv_l" vs_skip && [ -n "$("${_rv_l}_vs_skip" server)" ] && continue
      vs_start_server "$_rv_l" "$_rv_label"
    done
    for _rv_srv in $LIBS; do
      eval "_rv_port=\$SPORT_$_rv_srv"
      for _rv_cli in $LIBS; do
        VS_EXPECT=$VS_EXP; VS_NOTE=
        lib_has "$_rv_cli" vs_expect && "${_rv_cli}_vs_expect" "$_rv_s" "$_rv_srv"
        _rv_exp=$VS_EXPECT; _rv_note=$VS_NOTE
        _rv_skip=
        lib_has "$_rv_cli" vs_skip && _rv_skip=$("${_rv_cli}_vs_skip" client)
        [ -z "$_rv_skip" ] && lib_has "$_rv_srv" vs_skip && _rv_skip=$("${_rv_srv}_vs_skip" server)
        if [ -n "$_rv_skip" ]; then
          vs_rec "$_rv_s" "$_rv_cli" "$_rv_srv" "$_rv_exp" - "" "" "" "" SKIP "$_rv_skip"
          continue
        fi
        if ! vs_ensure "$_rv_srv" "$_rv_label"; then
          vs_rec "$_rv_s" "$_rv_cli" "$_rv_srv" "$_rv_exp" - "" "" "" "" FAIL \
            "$_rv_srv server failed to start (logs/server-$_rv_srv-$_rv_label.log)"
          continue
        fi
        _rv_log=$VSLOG/$_rv_s-$_rv_cli-to-$_rv_srv.log
        CAP_LABEL=$_rv_label; cap_begin "versions/$_rv_s/$_rv_cli-to-$_rv_srv" "$_rv_port"
        eval "_rv_pid=\$SPID_$_rv_srv"
        vs_client "$_rv_cli" "$_rv_port" brief >"$_rv_log" 2>&1
        cap_end
        vs_parse "$_rv_log" "$_rv_cli"
        # a refused handshake can leave a wolfSSL server exiting; make sure it is back
        vs_ensure "$_rv_srv" "$_rv_label" >/dev/null 2>&1
        if [ "$VS_OK" = 1 ]; then _rv_out=ok; else _rv_out=refused; fi
        # did the server process outlive the refusal? (same PID after vs_ensure)
        eval "_rv_pid2=\$SPID_$_rv_srv"; _rv_keeps=0
        [ "$_rv_out" = refused ] && [ -n "$_rv_pid" ] && [ "$_rv_pid2" = "$_rv_pid" ] && _rv_keeps=1
        _rv_hrr=no; _rv_pql=no
        if [ "$VS_OK" = 1 ]; then
          # s2nc reports a HelloRetryRequest; for the other clients infer it
          # from the negotiated group not being their first key share
          if [ -n "$VS_HRRSEEN" ]; then _rv_hrr=$VS_HRRSEEN
          elif [ "$VS_VER" = 1.3 ] && [ "$VS_GRP" != "$(vs_keyshare "$VS_CG")" ]; then _rv_hrr=yes; fi
          [ "$VS_CG" != classical ] && [ "$VS_KIND" = classical ] && _rv_pql=yes
        fi
        # compare with the expectation: refuse | V/classical | V/hybrid | V/pq | V/PQ (pq or hybrid)
        _rv_res=FAIL; _rv_det=
        case $_rv_exp in
          refuse)
            if [ "$VS_OK" = 0 ]; then _rv_res=PASS
            else _rv_det="expected a refusal but connected with TLS $VS_VER $VS_GRP"; fi ;;
          *)
            _rv_ev=${_rv_exp%%/*}; _rv_ek=${_rv_exp#*/}
            if [ "$VS_OK" = 0 ]; then
              _rv_det="expected TLS $_rv_ev $_rv_ek but the handshake failed: $(grep -iE 'alert|error' "$_rv_log" | head -n 1 | cut -c1-110)"
            elif [ "$VS_VER" != "$_rv_ev" ]; then
              _rv_det="expected TLS $_rv_ev, got TLS $VS_VER"
            elif [ "$_rv_ek" = PQ ] && { [ "$VS_KIND" = pq ] || [ "$VS_KIND" = hybrid ]; }; then
              _rv_res=PASS
            elif [ "$_rv_ek" = "$VS_KIND" ]; then
              _rv_res=PASS
            else
              _rv_det="expected a $_rv_ek group, got $VS_GRP"
            fi ;;
        esac
        [ -n "$_rv_note" ] && _rv_det="${_rv_det:+$_rv_det; }$_rv_note"
        [ "$_rv_res" = FAIL ] && _rv_det="$_rv_det (logs/versions/$(basename "$_rv_log"))"
        vs_rec "$_rv_s" "$_rv_cli" "$_rv_srv" "$_rv_exp" "$_rv_out" "$VS_VER" "$VS_GRP" "$_rv_hrr" "$_rv_pql" \
          "$_rv_res" "$_rv_det"
        [ -n "$_rv_note" ] && [ "$_rv_res" = PASS ] && printf '        note: %s\n' "$_rv_note"
        if [ "$VERSIONS_ITERATIONS" -gt 0 ]; then
          vs_time "$_rv_s" "$_rv_cli" "$_rv_srv" "$_rv_port" "$_rv_label" "$_rv_out" "$_rv_keeps"
        fi
      done
    done
    stop_servers
  done
  vs_summary
}

# median time for scenario/client/server from the summary file
vs_med() { awk -F, -v s="$1" -v c="$2" -v v="$3" 'NR>1 && $1==s && $2==c && $3==v && $12!="" {print $12}' "$VSSUM"; }

vs_summary() {
  VSSUM=$OUTDIR/versions_handshakes_summary.csv
  echo "scenario,client,server,outcome,version,group,hrr,pq_lost,handshake_rtts,n,min_ms,median_ms,mean_ms,p95_ms,max_ms,adj_median_ms" > "$VSSUM"
  awk -F, 'NR>1 {print $1","$2","$3","$10","$11","$12","$13","$14","$15}' "$VSCSV" |
  while IFS=, read -r _vs_s _vs_c _vs_v _vs_o _vs_ver _vs_g _vs_h _vs_p _vs_r; do
    eval "_vs_base=\$STARTUP_$_vs_c"
    _vs_st=$(awk -F, -v s="$_vs_s" -v c="$_vs_c" -v v="$_vs_v" 'NR>1 && $1==s && $2==c && $3==v {print $6}' "$VSRAW" |
             stats_line "$_vs_base")
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$_vs_s" "$_vs_c" "$_vs_v" "$_vs_o" "$_vs_ver" "$_vs_g" "$_vs_h" "$_vs_p" "$_vs_r" "$_vs_st" >> "$VSSUM"
  done

  hdr "Version/downgrade summary"
  {
    echo "category,pass,fail,skip"
    awk -F, 'NR>1 {if ($16=="PASS") p++; else if ($16=="FAIL") f++; else s++} END {printf "all cases,%d,%d,%d\n", p, f, s}' "$VSCSV"
  } | print_table
  _vs_fail=$(awk -F, 'NR>1 && $16=="FAIL" {printf "  %s %s->%s: %s\n", $1, $2, $3, $17}' "$VSCSV")
  [ -n "$_vs_fail" ] && printf '\nFailures:\n%s\n' "$_vs_fail"
  _vs_pql=$(awk -F, 'NR>1 && $14=="yes" {printf "  %s %s->%s: TLS %s %s%s\n", $1, $2, $3, $11, $12, ($13=="yes"?" (after HRR)":"")}' "$VSCSV")
  [ -n "$_vs_pql" ] && printf '\nConnections where the client offered post-quantum but got classical:\n%s\n' "$_vs_pql"

  [ "$VERSIONS_ITERATIONS" -gt 0 ] || return 0
  # client:server for every direction, and the matching column headers
  _vs_dirs=; _vs_hdr=
  for _vs_dc in $LIBS; do
    for _vs_ds in $LIBS; do _vs_dirs="$_vs_dirs $_vs_dc:$_vs_ds"; _vs_hdr="$_vs_hdr,$_vs_dc->$_vs_ds"; done
  done
  hdr "Version/downgrade timings: median ms [handshake round trips] (R = time to refusal)"
  {
    echo "scenario$_vs_hdr"
    for _vs_s in $VERSIONS_SCENARIOS; do
      vs_scenario "$_vs_s" >/dev/null 2>&1 || continue
      _vs_row=$_vs_s
      for _vs_d in $_vs_dirs; do
        set -- "${_vs_d%:*}" "${_vs_d#*:}"
        _vs_m=$(vs_med "$_vs_s" "$1" "$2")
        _vs_o=$(awk -F, -v s="$_vs_s" -v c="$1" -v v="$2" 'NR>1 && $1==s && $2==c && $3==v {print $4}' "$VSSUM")
        _vs_r=$(awk -F, -v s="$_vs_s" -v c="$1" -v v="$2" 'NR>1 && $1==s && $2==c && $3==v {print $9}' "$VSSUM")
        [ "$_vs_o" = refused ] && [ -n "$_vs_m" ] && _vs_m="R $_vs_m"
        [ -n "$_vs_m" ] && [ -n "$_vs_r" ] && _vs_m="$_vs_m [$_vs_r]"
        _vs_row="$_vs_row,${_vs_m:--}"
      done
      echo "$_vs_row"
    done
  } | print_table

  # key comparisons: difference of medians, per direction (same client in both,
  # so process startup cancels out)
  hdr "What negotiation and downgrade cost (difference of medians, ms)"
  {
    echo "comparison$_vs_hdr"
    while IFS='|' read -r _vs_a _vs_b _vs_lbl; do
      _vs_row=$_vs_lbl
      for _vs_d in $_vs_dirs; do
        set -- "${_vs_d%:*}" "${_vs_d#*:}"
        _vs_ma=$(vs_med "$_vs_a" "$1" "$2"); _vs_mb=$(vs_med "$_vs_b" "$1" "$2")
        if [ -n "$_vs_ma" ] && [ -n "$_vs_mb" ]; then
          _vs_row="$_vs_row,$(awk -v a="$_vs_ma" -v b="$_vs_mb" 'BEGIN{printf "%+.2f", a-b}')"
        else
          _vs_row="$_vs_row,-"
        fi
      done
      echo "$_vs_row"
    done <<'EOF_CMP'
neg13|base13|client negotiates 1.2-1.3 vs pinned 1.3
neg13-both|base13|both negotiate vs both pinned 1.3
base12|base13|TLS 1.2 vs TLS 1.3 (both pinned)
down12-server|base13|downgraded to 1.2 (server cap) vs native 1.3
down12-server|base12|downgraded to 1.2 (server cap) vs native 1.2
down12-client|base12|downgraded to 1.2 (client cap) vs native 1.2
hybrid13|base13|hybrid ML-KEM vs X25519 on TLS 1.3
hybrid-down12|hybrid13|hybrid client downgraded to 1.2 vs staying on 1.3
hybrid-hrr|base13|HelloRetryRequest to X25519 vs direct X25519
hybrid-hrr|hybrid13|HelloRetryRequest to X25519 vs hybrid without HRR
mldsa13|hybrid13|ML-DSA-65 cert vs ECDSA P-256 cert
refuse-13v12|base13|time to refusal vs a full 1.3 handshake
EOF_CMP
  } | print_table
  printf '\nPositive = the first scenario is slower. Each column compares the same client\n'
  printf 'and server programs, so process startup cancels out. For confidence intervals\n'
  printf 'run pqc_analyze.py on this run.\n'
  printf '\nThese are localhost timings, where a network round trip costs almost nothing.\n'
  printf 'On a real link each extra handshake round trip adds one full RTT: TLS 1.2 and a\n'
  printf 'HelloRetryRequest each add one over plain TLS 1.3. pqc_analyze.py --rtt MS\n'
  printf 'projects these timings onto a link with that round-trip time.\n'
}

# ----------------------------------------------------------------------------
# Packet capture (--capture)
#   Every checked handshake (the preflight in key-exchange mode, each mutual-TLS
#   check in ML-DSA mode, each case check in versions mode) is captured on the
#   loopback interface (--remote: the interface towards HOST, that host's
#   traffic only) into its own file. Session keys come from OpenSSL's
#   -keylogfile, s2n-tls's --key-log and, when wolfSSL is built with
#   --enable-keylog-export, from wolfSSL. With Wireshark's editcap the keys are
#   embedded in a .pcapng so it opens already decrypted; with tshark a decoded
#   transcript (.txt) is written next to it. Timed runs are never captured.
# ----------------------------------------------------------------------------
CAP_TOOL=; CAP_PID=; CAP_FILE=; CAP_NAME=; CAP_LABEL=; CAP_NEXT=; CLI_KEYS=
CAP_INJECT=0; CAP_TSHARK=0; CAPDIR=; CAP_HOST=

cap_setup() {
  CAPDIR=$OUTDIR/captures; mkdir -p "$CAPDIR/keys"
  if [ -n "$REMOTE" ]; then
    CAP_HOST=$CONNECT_HOST
    # the interface the route to HOST leaves by
    if [ -z "$CAPTURE_IFACE" ]; then
      case $(uname -s) in
        Darwin) CAPTURE_IFACE=$(route -n get "$CAP_HOST" 2>/dev/null | awk '$1 == "interface:" { print $2 }') ;;
        *)      CAPTURE_IFACE=$(ip route get "$CAP_HOST" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1) ;;
      esac
      [ -n "$CAPTURE_IFACE" ] || die "--capture: no route to $CAP_HOST found; set CAPTURE_IFACE"
    fi
  elif [ -z "$CAPTURE_IFACE" ]; then
    if [ "$(uname -s)" = Darwin ]; then CAPTURE_IFACE=lo0; else CAPTURE_IFACE=lo; fi
  fi
  if [ -z "$CAPTURE_TOOL" ]; then
    if have tcpdump; then CAPTURE_TOOL=tcpdump
    elif have dumpcap; then CAPTURE_TOOL=dumpcap
    else die "--capture needs tcpdump, or dumpcap from Wireshark"; fi
  fi
  have "$CAPTURE_TOOL" || die "capture tool '$CAPTURE_TOOL' not found"
  CAP_TOOL=$CAPTURE_TOOL

  # permission probe: capturing needs access to the packet-capture device
  _cs_err=$CAPDIR/probe.err
  cap_start_raw "$CAPDIR/probe.pcap" 1 "$_cs_err"
  if [ -z "$CAP_PID" ]; then
    printf '%s\n' "$(tail -n 3 "$_cs_err" 2>/dev/null)" >&2
    if [ "$(uname -s)" = Darwin ]; then
      die "cannot capture on $CAPTURE_IFACE. Install Wireshark and its ChmodBPF helper (grants capture access to your user), or run with sudo."
    else
      die "cannot capture on $CAPTURE_IFACE. Run with sudo, or allow it once: sudo setcap cap_net_raw,cap_net_admin=eip \"$(command -v "$CAP_TOOL")\""
    fi
  fi
  cap_stop_raw; rm -f "$CAPDIR/probe.pcap" "$_cs_err"

  if have editcap && editcap -h 2>&1 | grep -q -e '--inject-secrets'; then CAP_INJECT=1; fi
  if have tshark; then CAP_TSHARK=1; fi
  echo "file,mode,case,client,server,port,key_lines,decryptable,cert" > "$CAPDIR/index.csv"

  info "capture: $CAP_TOOL on $CAPTURE_IFACE -> $CAPDIR"
  [ "$CAP_INJECT" = 1 ] || warn "editcap (Wireshark) not found: keys are saved next to each .pcap instead of embedded"
  [ "$CAP_TSHARK" = 1 ] || warn "tshark not found: no decoded .txt transcripts"
  for _cs_l in $LIBS; do lib_has "$_cs_l" cap_setup && "${_cs_l}_cap_setup"; done
  warn "capture runs log session keys on every handshake; use a run without --capture for timing numbers"
}

# cap_start_raw FILE PORT ERRLOG -> CAP_PID (empty if the capture didn't start)
cap_start_raw() {
  CAP_PID=
  case $CAP_TOOL in
    tcpdump)
      # --immediate-mode: Linux otherwise hands packets over in ~1 s blocks and
      # stopping sooner loses them
      tcpdump -i "$CAPTURE_IFACE" -U -s 0 --immediate-mode -w "$1" "${CAP_HOST:+host $CAP_HOST and }tcp port $2" </dev/null >"$3" 2>&1 &
      ;;
    dumpcap)
      dumpcap -i "$CAPTURE_IFACE" -f "${CAP_HOST:+host $CAP_HOST and }tcp port $2" -w "$1" </dev/null >"$3" 2>&1 &
      ;;
  esac
  _cr_pid=$!
  _cr_i=0
  while [ $_cr_i -lt 60 ]; do
    if grep -qiE "listening on|capturing on" "$3" 2>/dev/null; then CAP_PID=$_cr_pid; return 0; fi
    kill -0 "$_cr_pid" 2>/dev/null || break
    sleep 0.1 2>/dev/null || sleep 1
    _cr_i=$((_cr_i + 1))
  done
  kill "$_cr_pid" 2>/dev/null; wait "$_cr_pid" 2>/dev/null
  return 1
}
cap_stop_raw() {
  [ -n "$CAP_PID" ] || return 0
  sleep 0.3 2>/dev/null || sleep 1   # let the last packets land
  kill -TERM "$CAP_PID" 2>/dev/null; wait "$CAP_PID" 2>/dev/null
  CAP_PID=
}

# cap_begin NAME PORT   (NAME like "kem/mldsa65/MLKEM768/openssl-to-wolfssl":
# kem/<cert>/<group>/..., mldsa/<profile>-<issuer>-chain/..., versions/<scenario>/...)
cap_begin() {
  [ "$CAPTURE" = 1 ] || return 0
  CAP_NAME=$1; CAP_PORT=$2
  CAP_FILE=$CAPDIR/$1.pcap
  mkdir -p "$(dirname "$CAP_FILE")"
  CLI_KEYS=$CAPDIR/keys/$(printf '%s' "$1" | tr '/' '_').client.keys
  : > "$CLI_KEYS"
  # drop anything wolfSSL wrote to its default key log before this case
  [ -f "$PWD/sslkeylog.log" ] && : > "$PWD/sslkeylog.log"
  if ! cap_start_raw "$CAP_FILE" "$2" "$CAP_FILE.err"; then
    warn "capture didn't start for $1 (see ${CAP_FILE#"$OUTDIR"/}.err)"
    CAP_FILE=
  fi
}

cap_end() {
  [ "$CAPTURE" = 1 ] || return 0
  cap_stop_raw
  [ -n "$CAP_FILE" ] || { CLI_KEYS=; return 0; }
  rm -f "$CAP_FILE.err"
  _ce_mode=${CAP_NAME%%/*}; _ce_rest=${CAP_NAME#*/}; _ce_case=${_ce_rest%/*}; _ce_dir=${CAP_NAME##*/}
  # key-exchange mode: kem/<cert>/<group>/...
  _ce_cert=
  if [ "$_ce_mode" = kem ]; then _ce_cert=${_ce_case%%/*}; _ce_case=${_ce_case#*/}; fi
  _ce_cli=${_ce_dir%%-to-*}; _ce_srv=${_ce_dir#*-to-}; _ce_srv=${_ce_srv%%-*}
  _ce_base=${CAP_FILE%.pcap}
  _ce_keys=$_ce_base.keys
  # --remote: the server's session file comes from HOST
  [ -n "$REMOTE" ] && remote_get "$CAPDIR/keys/server-$_ce_srv-$CAP_LABEL.keys"
  # only keys this connection's own client and server wrote: the client's per-case
  # file, the server's session file, and wolfSSL's default file (builds without
  # the SSLKEYLOGFILE override write there; we run from WOLFSSL_DIR)
  {
    cat "$CLI_KEYS" 2>/dev/null
    cat "$CAPDIR/keys/server-$_ce_srv-$CAP_LABEL.keys" 2>/dev/null
    [ -f "$PWD/sslkeylog.log" ] && cat "$PWD/sslkeylog.log"
  } | sort -u > "$_ce_keys"
  [ -f "$PWD/sslkeylog.log" ] && : > "$PWD/sslkeylog.log"
  rm -f "$CLI_KEYS"
  _ce_lines=$(wc -l < "$_ce_keys" | tr -d ' ')
  # decryptable when a program that logs keys took part (<id>_keylogs: OpenSSL
  # and s2n-tls always do, wolfSSL only with --enable-keylog-export) and keys
  # were written
  _ce_dec=no
  if [ "$_ce_lines" -gt 0 ] && { "${_ce_cli}_keylogs" || "${_ce_srv}_keylogs"; }; then
    _ce_dec=yes
  fi
  _ce_out=$CAP_FILE
  if [ "$_ce_lines" -eq 0 ]; then
    rm -f "$_ce_keys"
  elif [ "$CAP_INJECT" = 1 ] &&
       editcap --inject-secrets "tls,$_ce_keys" "$CAP_FILE" "$_ce_base.pcapng" >/dev/null 2>&1; then
    rm -f "$CAP_FILE" "$_ce_keys"
    _ce_out=$_ce_base.pcapng
  fi
  if [ "$CAP_TSHARK" = 1 ]; then
    set -- -r "$_ce_out" -o "http.tls.port:$BASE_PORT-$((BASE_PORT + 999))" -Y "tls || tcp.flags.syn==1"
    [ -f "$_ce_keys" ] && set -- "$@" -o "tls.keylog_file:$_ce_keys"
    tshark "$@" 2>/dev/null > "$_ce_base.txt"
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "${_ce_out#"$CAPDIR"/}" "$_ce_mode" "$_ce_case" "$_ce_cli" "$_ce_srv" \
    "$CAP_PORT" "$_ce_lines" "$_ce_dec" "$_ce_cert" >> "$CAPDIR/index.csv"
  CLI_KEYS=
}

# SSLKEYLOGFILE value for a client run: this case's key file while a capture is
# active, /dev/null for other runs of a capture session (keeps wolfSSL key-log
# builds from filling their default file), otherwise whatever the user has set
cli_keylog_val() {
  if [ -n "$CLI_KEYS" ]; then printf '%s\n' "$CLI_KEYS"
  elif [ "$CAPTURE" = 1 ]; then echo /dev/null
  else printf '%s\n' "${SSLKEYLOGFILE:-}"; fi
}
# server key-log file for IMPL/LABEL when capturing, otherwise empty
srv_keys() { if [ "$CAPTURE" = 1 ]; then printf '%s\n' "$CAPDIR/keys/server-$1-$2.keys"; fi; }

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
# --serve: HOST's agent for a --remote run, until the run ends
if [ -n "$SERVE" ]; then serve_loop; exit 0; fi
netsim_up
remote_up
if [ "$CAPTURE" = 1 ]; then
  if [ "$DO_HS" = 1 ]; then cap_setup; else warn "--capture has nothing to capture with --primitives-only"; CAPTURE=0; fi
fi
if [ "$DO_PRIM" = 1 ]; then
  [ "$DO_KEM" = 1 ]   && run_primitives kem
  [ "$DO_MLDSA" = 1 ] && run_primitives mldsa
fi
if [ "$DO_HS" = 1 ]; then
  if [ "$DO_KEM" = 1 ]; then run_handshakes; summarize; fi
  [ "$DO_MLDSA" = 1 ] && run_mldsa
  if [ "$DO_VERSIONS" = 1 ]; then
    : "${VERSIONS_SCENARIOS:=$VS_ALL}"
    run_versions
  fi
fi

hdr "Done"
[ -n "$SUMMARY" ] && info "key exchange handshakes:   $SUMMARY (raw: $RAW)"
[ -n "$MLCSV" ]   && info "ML-DSA interop results:    $MLCSV"
[ -n "$MLSUM" ]   && info "ML-DSA handshakes:         $MLSUM (raw: $MLRAW)"
[ -n "$INSUM" ]   && info "in-process key exchange:   $INSUM (raw: $INRAW)"
[ -n "$MLINSUM" ] && info "in-process ML-DSA:         $MLINSUM (raw: $MLINRAW)"
[ -n "$VSCSV" ]   && info "version/downgrade cases:   $VSCSV"
[ -n "$VSSUM" ]   && info "version/downgrade timings: $VSSUM (raw: $VSRAW)"
[ "$DO_PRIM" = 1 ] && info "primitive outputs:         $OUTDIR/primitives/"
[ "$CAPTURE" = 1 ] && info "packet captures:           $CAPDIR/ (index.csv lists them)"
info "logs:                      $LOGDIR/"

# Non-zero exit if any ML-DSA interop check failed (handy for CI)
if [ -n "$MLCSV" ] && awk -F, 'NR>1 && $7=="FAIL" {f=1} END{exit !f}' "$MLCSV"; then
  exit 1
fi
if [ -n "$VSCSV" ] && awk -F, 'NR>1 && $16=="FAIL" {f=1} END{exit !f}' "$VSCSV"; then
  exit 1
fi
exit 0
