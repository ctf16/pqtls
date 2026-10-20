#!/bin/sh
# =============================================================================
# setup.sh — fetch and build the TLS libraries that pqcbench.sh tests
#
# Portable POSIX sh (macOS, and Linux with glibc or musl). Everything goes in
# this script's directory, where pqcbench.sh finds it without any settings:
#   openssl/         OpenSSL, installed to openssl/openssl-install (static)
#   wolfssl/         wolfSSL with the PQC configuration from README.md
#   wolfssl-keylog/  the same wolfSSL plus TLS key logging, only for
#                    decryptable wolfSSL->wolfSSL captures (never for timing)
#   aws-lc/          AWS-LC, installed to aws-lc/aws-lc-install (bssl)
#   s2n-tls/         s2n-tls's s2nc, s2nd and policy, linked to that AWS-LC
#   hsloop/bin/      hsloop-openssl, hsloop-wolfssl, hsloop-s2n: clients that
#                    time many handshakes in one process (pqcbench.sh --inproc),
#                    each linked statically to the library built above
#   rustls-tools/    rustls 0.23 tools for pqcbench.sh, built once per crypto
#                    provider (RUSTLS_PROVIDERS): bin/pqc-rustls-<provider>
#                    (client, server, capabilities, primitive benchmark) and
#                    hsloop/bin/hsloop-rustls-<provider>. The wolfcrypt
#                    provider is fetched into rustls-wolfcrypt/ and patched to
#                    build the wolfSSL above (optimized) instead of its own
#                    debug build of wolfSSL 5.9.1. graviola-pq,
#                    rustcrypto-pq and libcrux-pq are this project's
#                    providers, published on crates.io: on graviola, the
#                    current RustCrypto crates and the libcrux crates
#
# FIPS builds (--fips; pqcbench.sh --fips uses them), next to the ones above:
#   openssl-fips/    the OpenSSL FIPS provider from OPENSSL_FIPS_REF, installed
#                    to openssl-fips/openssl-fips-install (lib/ossl-modules/,
#                    ssl/fipsmodule.cnf and ssl/openssl-fips.cnf); the OpenSSL
#                    above loads it, as a FIPS deployment of a newer OpenSSL does
#   wolfssl-fips/    wolfSSL's GPLv3 FIPS Ready bundle (wolfCrypt FIPS v7 code,
#                    --enable-fips=ready), shared library installed to
#                    wolfssl-fips/wolfssl-fips-install: the FIPS integrity hash
#                    of a static library would differ in every program
#   aws-lc/aws-lc-fips-install   AWS-LC with -DFIPS=1 (build tree aws-lc/build-fips);
#                    static on Linux, shared on macOS (AWS-LC builds a static
#                    FIPS module on Linux only); always with CPU-jitter entropy
#   s2n-tls/build-fips/  s2nc, s2nd and policy linked to that AWS-LC
#   hsloop/bin/      hsloop-wolfssl-fips, hsloop-s2n-fips, linked to those
#                    (hsloop-openssl serves both: it loads the FIPS provider
#                    named by OPENSSL_CONF)
#   None of these is a CMVP-validated module: they run the FIPS module code
#   in FIPS mode (see README.md "FIPS mode").
#
# An existing component directory is used as it is (not fetched again), and
# an already built component is skipped unless --rebuild is given. Build
# output goes to <component>/pqc-setup.log (pqc-setup-fips.log for aws-lc-fips
# and s2n-tls-fips, which share the aws-lc/ and s2n-tls/ source trees).
#
# Usage:
#   ./setup.sh [options] [component ...]
#
# Components: openssl wolfssl wolfssl-keylog aws-lc s2n-tls rustls hsloop
#             openssl-fips wolfssl-fips aws-lc-fips s2n-tls-fips
#   Default: openssl wolfssl aws-lc s2n-tls rustls hsloop (rustls only when a
#   Rust toolchain is installed; --deps installs rustup). s2n-tls builds
#   aws-lc first if it isn't built yet (s2n-tls-fips: aws-lc-fips;
#   openssl-fips: openssl). aws-lc needs Go (1.20 or later), which --deps
#   installs. Every run also rebuilds the hsloop clients whose library or
#   source changed (a few seconds), so they never link a stale library, and
#   runs cargo for rustls (which rebuilds only what changed).
#
# Options:
#   --deps         first install the build and run-time packages (apt-get,
#                  apk or Homebrew; uses sudo when not root)
#   --deps-only    only install the packages
#   --rebuild      rebuild the components from a clean build tree, even if
#                  they are already built
#   --fips         build the FIPS components: with no component named,
#                  openssl-fips wolfssl-fips aws-lc-fips s2n-tls-fips (and the
#                  hsloop clients); named components map to their FIPS builds
#                  (openssl -> openssl-fips, ...). The non-FIPS builds stay.
#   -j, --jobs N   parallel build jobs (default: number of CPUs)
#   --awslc-no-jitter  build AWS-LC without its CPU-jitter entropy source
#                  (DISABLE_CPU_JITTER_ENTROPY): its random number generator
#                  is then seeded from the OS only, like OpenSSL and wolfSSL
#                  here. Removes ~17 ms of per-process seeding from every s2n-tls
#                  handshake; not AWS-LC's default and not FIPS-eligible. For
#                  benchmarking only. Rebuilds AWS-LC and s2n-tls if the
#                  existing build differs. Applies to the non-FIPS AWS-LC only:
#                  the FIPS build (aws-lc-fips) always uses CPU jitter. Also
#                  rustls's aws-lc-rs provider (AWS_LC_SYS_NO_JITTER_ENTROPY).
#   --awslc-jitter the stock AWS-LC entropy configuration (the default for a
#                  new build); rebuilds AWS-LC and s2n-tls if the existing
#                  build is a no-jitter one. Without either flag an existing
#                  AWS-LC build is kept as it is.
#   -h, --help
#
# Environment:
#   OPENSSL_REF    OpenSSL git tag (default openssl-3.6.5)
#   OPENSSL_FIPS_REF  OpenSSL git tag of the FIPS provider (default openssl-3.5.4,
#                  the version submitted for FIPS 140-3 validation; any 3.5+ tag
#                  works, e.g. OPENSSL_REF's for the provider of the same release)
#   WOLFSSL_REF    wolfSSL git tag (default v5.9.4-stable)
#   WOLFSSL_FIPS_URL  wolfSSL FIPS Ready zip (default: the one for WOLFSSL_REF,
#                  https://www.wolfssl.com/wolfssl-<version>-gplv3-fips-ready.zip)
#   WOLFSSL_FIPS_SRC  a local FIPS Ready (or licensed FIPS) zip or source
#                  directory to use instead of downloading WOLFSSL_FIPS_URL
#   AWSLC_REF      AWS-LC git tag (default v5.10.0)
#   S2N_REF        s2n-tls git tag (default v1.7.10)
#   RUSTLS_PROVIDERS  rustls crypto providers to build (default: aws-lc-rs ring
#                  graviola graviola-pq rustcrypto rustcrypto-pq libcrux-pq
#                  wolfcrypt);
#                  rustls itself is pinned in rustls-tools/Cargo.toml
#   RUSTLS_WOLFCRYPT_REF  rustls-wolfcrypt-provider commit (default: the tested one)
#   JOBS           same as --jobs
#   AWSLC_NO_JITTER  1 = --awslc-no-jitter, 0 = --awslc-jitter
#   EXTRA_CA_FILE  PEM file of CA certificates to trust for downloads, on top
#                  of the system store (for TLS-inspecting proxies)
#   CC, CXX, CFLAGS, SDKROOT   passed through to the builds
#
# The tags are the releases pqcbench.sh was tested with. A newer s2n-tls can
# rename security policies the script uses (see README.md).
# =============================================================================

: "${OPENSSL_REF:=openssl-3.6.5}"
: "${OPENSSL_FIPS_REF:=openssl-3.5.4}"
: "${WOLFSSL_REF:=v5.9.4-stable}"
: "${WOLFSSL_FIPS_SRC:=}"
_wf_v=${WOLFSSL_REF#v}
: "${WOLFSSL_FIPS_URL:=https://www.wolfssl.com/wolfssl-${_wf_v%-stable}-gplv3-fips-ready.zip}"
: "${AWSLC_REF:=v5.10.0}"
: "${AWSLC_NO_JITTER:=}"
: "${S2N_REF:=v1.7.10}"
RUSTLS_PROVIDERS_ALL="aws-lc-rs ring graviola graviola-pq rustcrypto rustcrypto-pq libcrux-pq wolfcrypt"
: "${RUSTLS_PROVIDERS:=$RUSTLS_PROVIDERS_ALL}"
: "${RUSTLS_WOLFCRYPT_REF:=b6457e0524bba789016357566584d8313d59958d}"
: "${JOBS:=}"
: "${EXTRA_CA_FILE:=}"

ROOT=$(cd "$(dirname "$0")" && pwd) || exit 1

# wolfSSL configuration (README "Building wolfSSL"); the assembly flag follows the CPU.
# CPPFLAGS=-DWOLFSSL_ALT_NAMES (no configure option of its own): the helper's
# wolfSSL-issued ML-DSA leaves get the same subjectAltName as the OpenSSL-issued
# ones (rustls ignores the CN).
WOLF_FLAGS="--enable-mlkem --enable-mldsa --enable-curve25519 --enable-ed25519
--enable-tls13 --enable-tls-mlkem-standalone
--enable-certgen --enable-certext --enable-keygen
--enable-sp --enable-sp-asm --disable-shared CPPFLAGS=-DWOLFSSL_ALT_NAMES"
# FIPS Ready (wolfCrypt FIPS v7): the same, as a shared library (one FIPS
# integrity hash for every program). No Curve25519: --enable-fips=ready turns
# it off (X25519 isn't FIPS-approved), so there is no X25519MLKEM768 either.
WOLF_FIPS_FLAGS="--enable-fips=ready --enable-mlkem --enable-mldsa --enable-ed25519
--enable-tls13 --enable-tls-mlkem-standalone
--enable-certgen --enable-certext --enable-keygen
--enable-sp --enable-sp-asm --enable-shared --disable-static CPPFLAGS=-DWOLFSSL_ALT_NAMES"

# packages for --deps: compilers and build tools, plus what pqcbench.sh uses at
# run time (GNU date and timeout, ss from iproute2, tcpdump for --capture, perl
# for --remote's round-trip timing). Go is required
# for AWS-LC's code generation; curl and unzip fetch the wolfSSL FIPS Ready zip;
# rustup brings the Rust toolchain rustls-tools pins, and libclang serves the
# wolfcrypt rustls provider's bindgen. On musl (Alpine) Rust's static libraries
# need the system's libunwind (llvm-libunwind-dev) to link the hsloop clients.
APT_PKGS="ca-certificates git build-essential autoconf automake libtool pkg-config cmake perl golang-go
coreutils iproute2 tcpdump curl unzip rustup libclang-dev"
APK_PKGS="ca-certificates git build-base autoconf automake libtool pkgconf cmake perl go linux-headers
coreutils iproute2 tcpdump curl unzip rustup clang-dev llvm-libunwind-dev"
BREW_PKGS="autoconf automake libtool cmake go coreutils rustup"

if [ -t 1 ]; then
  C_B=$(printf '\033[1m'); C_CY=$(printf '\033[36m'); C_BL=$(printf '\033[34m')
  C_YL=$(printf '\033[33m'); C_RD=$(printf '\033[31m'); C_0=$(printf '\033[0m')
else
  C_B=; C_CY=; C_BL=; C_YL=; C_RD=; C_0=
fi
hdr()  { printf '\n%s%s== %s ==%s\n' "$C_B" "$C_CY" "$*" "$C_0"; }
info() { printf '%s*%s %s\n' "$C_BL" "$C_0" "$*"; }
warn() { printf '%s!%s %s\n' "$C_YL" "$C_0" "$*" >&2; }
die()  { printf '%sx%s %s\n' "$C_RD" "$C_0" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
usage() { sed -n '3,/^# =====*$/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

# ----------------------------------------------------------------------------
# Args
# ----------------------------------------------------------------------------
DO_DEPS=0; DEPS_ONLY=0; REBUILD=0; COMPONENTS=; FIPS=0; RUSTLS_DEFAULT=0
while [ $# -gt 0 ]; do
  case $1 in
    -h|--help)   usage; exit 0 ;;
    --deps)      DO_DEPS=1; shift ;;
    --deps-only) DO_DEPS=1; DEPS_ONLY=1; shift ;;
    --rebuild)   REBUILD=1; shift ;;
    --fips)      FIPS=1; shift ;;
    --awslc-no-jitter) AWSLC_NO_JITTER=1; shift ;;
    --awslc-jitter)    AWSLC_NO_JITTER=0; shift ;;
    -j|--jobs)   [ $# -ge 2 ] || die "$1 needs a value"; JOBS=$2; shift 2 ;;
    --jobs=*)    JOBS=${1#*=}; shift ;;
    openssl|wolfssl|wolfssl-keylog|aws-lc|s2n-tls|rustls|hsloop|openssl-fips|wolfssl-fips|aws-lc-fips|s2n-tls-fips|rustls-fips)
      COMPONENTS="$COMPONENTS $1"; shift ;;
    *) printf 'unknown option or component: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ "$FIPS" = 1 ]; then
  if [ -z "$COMPONENTS" ]; then
    COMPONENTS="openssl-fips wolfssl-fips aws-lc-fips s2n-tls-fips rustls-fips hsloop"
    RUSTLS_DEFAULT=1
  else
    _a_c=
    for _a_x in $COMPONENTS; do
      case $_a_x in
        openssl|wolfssl|aws-lc|s2n-tls|rustls) _a_x=$_a_x-fips ;;
        wolfssl-keylog) die "wolfssl-keylog has no FIPS build" ;;
      esac
      _a_c="$_a_c $_a_x"
    done
    COMPONENTS=$_a_c
  fi
fi
# rustls is part of the default build when a Rust toolchain is installed
# (otherwise it is skipped with a warning); named, it must build
if [ -z "$COMPONENTS" ]; then
  COMPONENTS="openssl wolfssl aws-lc s2n-tls rustls hsloop"
  RUSTLS_DEFAULT=1
fi
if [ -z "$JOBS" ]; then
  JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
fi
case $JOBS in ''|0|*[!0-9]*) die "--jobs needs a positive integer" ;; esac
case $AWSLC_NO_JITTER in ''|0|1) ;; *) die "AWSLC_NO_JITTER must be 0 or 1" ;; esac
want() { case " $COMPONENTS " in *" $1 "*) return 0 ;; esac; return 1; }

# ----------------------------------------------------------------------------
# Extra CA certificates (TLS-inspecting proxies): a temporary bundle of the
# system store plus EXTRA_CA_FILE, for git, curl and OpenSSL-based tools
# (apk). Rebuilt after --deps, which may install the system store.
# ----------------------------------------------------------------------------
CA_BUNDLE=; FETCH_TMP=
trap '[ -z "$CA_BUNDLE" ] || rm -f "$CA_BUNDLE"; [ -z "$FETCH_TMP" ] || rm -rf "$FETCH_TMP"' EXIT
trap 'exit 130' INT TERM
ca_setup() {
  [ -n "$EXTRA_CA_FILE" ] || return 0
  [ -f "$EXTRA_CA_FILE" ] || die "EXTRA_CA_FILE=$EXTRA_CA_FILE not found"
  if [ -z "$CA_BUNDLE" ]; then
    CA_BUNDLE=$(mktemp "${TMPDIR:-/tmp}/pqc-setup-ca.XXXXXX") || die "mktemp failed"
  fi
  {
    for _cs_f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
      if [ -f "$_cs_f" ]; then cat "$_cs_f"; break; fi
    done
    cat "$EXTRA_CA_FILE"
  } > "$CA_BUNDLE"
  SSL_CERT_FILE=$CA_BUNDLE; GIT_SSL_CAINFO=$CA_BUNDLE; CURL_CA_BUNDLE=$CA_BUNDLE; CARGO_HTTP_CAINFO=$CA_BUNDLE
  export SSL_CERT_FILE GIT_SSL_CAINFO CURL_CA_BUNDLE CARGO_HTTP_CAINFO
}

# ----------------------------------------------------------------------------
# --deps
# ----------------------------------------------------------------------------
as_root() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  elif have sudo; then
    # shellcheck disable=SC2086
    sudo env ${SSL_CERT_FILE:+SSL_CERT_FILE=$SSL_CERT_FILE} "$@"
  else
    die "--deps needs root or sudo"
  fi
}
install_deps() {
  hdr "Packages"
  if [ "$(uname -s)" = Darwin ]; then
    have brew || die "--deps on macOS needs Homebrew (https://brew.sh); the Xcode command line tools provide git and the compilers"
    info "brew install $(echo $BREW_PKGS)"
    # shellcheck disable=SC2086
    brew install $BREW_PKGS || die "brew install failed"
  elif have apt-get; then
    set -- -q
    [ -n "$CA_BUNDLE" ] && set -- "$@" -o "Acquire::https::CAInfo=$CA_BUNDLE"
    info "apt-get install $(echo $APT_PKGS)"
    as_root env DEBIAN_FRONTEND=noninteractive apt-get "$@" update || die "apt-get update failed"
    # shellcheck disable=SC2086
    as_root env DEBIAN_FRONTEND=noninteractive apt-get "$@" install -y --no-install-recommends $APT_PKGS \
      || die "apt-get install failed"
  elif have apk; then
    info "apk add $(echo $APK_PKGS)"
    # shellcheck disable=SC2086
    as_root apk add --no-cache $APK_PKGS || die "apk add failed"
  else
    die "--deps knows apt-get, apk and Homebrew. Install by hand: git, a C/C++ toolchain with make, autoconf, automake, libtool, pkg-config, cmake, perl, Go 1.20+, Linux headers; for pqcbench.sh GNU coreutils (date, timeout), ss (iproute2) and tcpdump"
  fi
}

# ----------------------------------------------------------------------------
# Building blocks
# ----------------------------------------------------------------------------
# fetch DIR URL REF: shallow clone of REF, unless DIR already exists
fetch() {
  if [ -e "$ROOT/$1" ]; then
    _fe_v=$(git -C "$ROOT/$1" describe --tags --always 2>/dev/null)
    info "using the existing $1/ (${_fe_v:-not a git checkout})"
    case $_fe_v in
      ''|"$3"|"$3"-*) ;;
      *) warn "$1/ is at $_fe_v, not $3 (delete $1/ to fetch $3)" ;;
    esac
    return 0
  fi
  have git || die "git not found (./setup.sh --deps installs it)"
  info "fetching $3 from $2"
  # stderr only on failure: shallow clones of annotated tags warn "... is not a commit!"
  if ! _fe_err=$(git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$3" "$2" "$ROOT/$1" 2>&1); then
    printf '%s\n' "$_fe_err" >&2
    die "$1: git clone of $3 failed${EXTRA_CA_FILE:+ (EXTRA_CA_FILE=$EXTRA_CA_FILE)}"
  fi
}

# fetch_wolfssl_fips: the wolfSSL FIPS Ready source into wolfssl-fips/, from
# WOLFSSL_FIPS_SRC (a zip or a source directory) or a download of
# WOLFSSL_FIPS_URL, unless wolfssl-fips/ exists. Its WOLFF_ORIGIN file
# records where it came from (it isn't a git checkout).
WOLFF_ORIGIN=.pqc-fips-source
fetch_wolfssl_fips() {
  _ff_d=$ROOT/wolfssl-fips
  if [ -e "$_ff_d" ]; then
    info "using the existing wolfssl-fips/ ($(cat "$_ff_d/$WOLFF_ORIGIN" 2>/dev/null || echo "origin unknown"))"
    return 0
  fi
  if [ -n "$WOLFSSL_FIPS_SRC" ] && [ -d "$WOLFSSL_FIPS_SRC" ]; then
    info "copying $WOLFSSL_FIPS_SRC"
    cp -R "$WOLFSSL_FIPS_SRC" "$_ff_d" || die "wolfssl-fips: copying $WOLFSSL_FIPS_SRC failed"
    _ff_o=$WOLFSSL_FIPS_SRC
  else
    have unzip || die "unzip not found (./setup.sh --deps installs it)"
    FETCH_TMP=$(mktemp -d "${TMPDIR:-/tmp}/pqc-setup-fetch.XXXXXX") || die "mktemp failed"
    if [ -n "$WOLFSSL_FIPS_SRC" ]; then
      [ -f "$WOLFSSL_FIPS_SRC" ] || die "WOLFSSL_FIPS_SRC=$WOLFSSL_FIPS_SRC not found"
      _ff_zip=$WOLFSSL_FIPS_SRC
    else
      have curl || die "curl not found (./setup.sh --deps installs it)"
      info "downloading $WOLFSSL_FIPS_URL"
      _ff_zip=$FETCH_TMP/src.zip
      curl -fsSL -o "$_ff_zip" "$WOLFSSL_FIPS_URL" ||
        die "wolfssl-fips: download of $WOLFSSL_FIPS_URL failed${EXTRA_CA_FILE:+ (EXTRA_CA_FILE=$EXTRA_CA_FILE)}"
    fi
    unzip -q "$_ff_zip" -d "$FETCH_TMP/x" || die "wolfssl-fips: unzip of $_ff_zip failed"
    set -- "$FETCH_TMP"/x/*
    { [ $# = 1 ] && [ -d "$1" ]; } || die "wolfssl-fips: $_ff_zip doesn't hold one top-level directory"
    mv "$1" "$_ff_d" || die "wolfssl-fips: mv failed"
    rm -rf "$FETCH_TMP"; FETCH_TMP=
    _ff_o=${WOLFSSL_FIPS_SRC:-$WOLFSSL_FIPS_URL}
  fi
  [ -f "$_ff_d/wolfcrypt/src/fips.c" ] ||
    die "wolfssl-fips/ has no wolfcrypt/src/fips.c, so it isn't a FIPS source tree (delete it; check WOLFSSL_FIPS_SRC/WOLFSSL_FIPS_URL)"
  printf '%s\n' "$(basename "$_ff_o")" > "$_ff_d/$WOLFF_ORIGIN"
}

# in_dir DIR CMD...: run CMD in DIR
in_dir() { ( cd "$1" && shift && "$@" ); }

# step CMD...: run CMD with its output appended to $LOG; on failure show the
# end of the log and stop
step() {
  printf '$ %s\n' "$*" >> "$LOG"
  if ! "$@" >> "$LOG" 2>&1; then
    tail -n 30 "$LOG" >&2
    die "$COMP: '$1 ...' failed (full log: ${LOG#"$ROOT"/})"
  fi
}

# elapsed seconds since START (for progress lines)
since() { echo "$(( $(date +%s) - START ))s"; }

case $(uname -m) in
  aarch64|arm64) WOLF_ASM=--enable-armasm ;;
  x86_64|amd64)  WOLF_ASM=--enable-intelasm ;;
  *)             WOLF_ASM= ;;
esac

# ----------------------------------------------------------------------------
# Components
# ----------------------------------------------------------------------------
OSSL_BIN=$ROOT/openssl/openssl-install/bin/openssl
BSSL_BIN=$ROOT/aws-lc/aws-lc-install/bin/bssl
# FIPS builds
if [ "$(uname -s)" = Darwin ]; then DSO_EXT=dylib; else DSO_EXT=so; fi
OSSLF_I=$ROOT/openssl-fips/openssl-fips-install
OSSLF_MODDIR=$OSSLF_I/lib/ossl-modules
OSSLF_CNF=$OSSLF_I/ssl/openssl-fips.cnf
WOLFF_D=$ROOT/wolfssl-fips
WOLFF_I=$WOLFF_D/wolfssl-fips-install
AWSLCF_I=$ROOT/aws-lc/aws-lc-fips-install
BSSLF_BIN=$AWSLCF_I/bin/bssl
S2NF_B=$ROOT/s2n-tls/build-fips

build_openssl() {
  COMP=openssl; _bo_d=$ROOT/openssl
  hdr "OpenSSL ($OPENSSL_REF)"
  if [ "$REBUILD" = 0 ] && [ -x "$OSSL_BIN" ]; then
    info "already built: $("$OSSL_BIN" version) (--rebuild to build again)"; return 0
  fi
  fetch openssl https://github.com/openssl/openssl.git "$OPENSSL_REF"
  LOG=$_bo_d/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  if [ -f "$_bo_d/Makefile" ]; then step make -C "$_bo_d" distclean; fi
  rm -rf "$_bo_d/openssl-install"
  # static: the openssl binary can't pick up an older system libcrypto.
  # enable-ec_nistp_64_gcc_128: OpenSSL's 64-bit P-224/P-384/P-521 code (off by
  # default); without it P-384 runs on generic bignum code, ~10x slower than the
  # other libraries' P-384 and the SecP384r1MLKEM1024 hybrid with it
  info "configure (static, enable-ec_nistp_64_gcc_128, prefix openssl/openssl-install)"
  step in_dir "$_bo_d" ./Configure --prefix="$_bo_d/openssl-install" \
    --openssldir="$_bo_d/openssl-install/ssl" --libdir=lib no-shared no-tests no-docs \
    enable-ec_nistp_64_gcc_128
  info "make -j $JOBS"
  step make -C "$_bo_d" -j "$JOBS"
  step make -C "$_bo_d" install_sw install_ssldirs
  info "built in $(since): $("$OSSL_BIN" version)"
}

# 0 if DIR's last configure had every option in FLAGS (so a tree built before
# setup.sh added an option is rebuilt)
configured_with() { # DIR FLAGS
  _cw=$(sed -n 's/^ac_cs_config=//p' "$1/config.status" 2>/dev/null | tr -d "'\"")
  for _cw_f in $2; do case " $_cw " in *" $_cw_f "*) ;; *) return 1 ;; esac; done
}

build_wolfssl() { # DIR [extra configure args...]
  COMP=$1; _bw_d=$ROOT/$1; shift
  hdr "$COMP ($WOLFSSL_REF)"
  if [ "$REBUILD" = 0 ] && [ -f "$_bw_d/wolfssl/options.h" ] &&
     [ -x "$_bw_d/examples/client/client" ] && [ -x "$_bw_d/examples/server/server" ]; then
    if configured_with "$_bw_d" "$WOLF_FLAGS"; then info "already built (--rebuild to build again)"; return 0; fi
    info "built without some of today's configure options: building again"
  fi
  fetch "$COMP" https://github.com/wolfSSL/wolfssl.git "$WOLFSSL_REF"
  LOG=$_bw_d/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  if [ ! -x "$_bw_d/configure" ]; then info "autogen.sh"; step in_dir "$_bw_d" ./autogen.sh; fi
  if [ -f "$_bw_d/Makefile" ]; then step make -C "$_bw_d" distclean; fi
  [ -n "$WOLF_ASM" ] || warn "no wolfSSL assembly option for $(uname -m): building without --enable-armasm/--enable-intelasm"
  info "configure ($(echo $WOLF_FLAGS $WOLF_ASM "$@"))"
  # shellcheck disable=SC2086
  step in_dir "$_bw_d" ./configure $WOLF_FLAGS $WOLF_ASM "$@"
  info "make -j $JOBS"
  step make -C "$_bw_d" -j "$JOBS"
  info "built in $(since)"
}

# entropy configuration of the existing AWS-LC build: 1 = no CPU jitter,
# 0 = stock, empty = unknown (not built, or no CMake cache)
awslc_built_no_jitter() {
  _ab_c=$ROOT/aws-lc/build/CMakeCache.txt
  [ -x "$BSSL_BIN" ] && [ -f "$_ab_c" ] || return 0
  case $(sed -n 's/^DISABLE_CPU_JITTER_ENTROPY:BOOL=//p' "$_ab_c") in
    ON|on|TRUE|true|1|YES|yes) echo 1 ;;
    *) echo 0 ;;
  esac
}
jitter_desc() {
  case $1 in
    1) echo "no CPU jitter (OS entropy only)" ;;
    0) echo "CPU-jitter entropy (stock)" ;;
    *) echo "entropy configuration unknown" ;;
  esac
}

# set when this run (re)builds AWS-LC: s2n-tls links its libcrypto.a statically
AWSLC_BUILT=0
build_awslc() {
  COMP=aws-lc; _ba_d=$ROOT/aws-lc
  hdr "AWS-LC ($AWSLC_REF)"
  _ba_have=$(awslc_built_no_jitter)
  if [ "$REBUILD" = 0 ] && [ -x "$BSSL_BIN" ] && [ "$AWSLC_MISMATCH" = 0 ]; then
    info "already built, $(jitter_desc "$_ba_have") (--rebuild to build again)"; return 0
  fi
  # --rebuild without a jitter flag keeps the existing build's configuration
  _ba_nj=${AWSLC_NO_JITTER:-${_ba_have:-0}}
  if [ "$AWSLC_MISMATCH" = 1 ]; then
    info "existing build: $(jitter_desc "$_ba_have"); rebuilding with $(jitter_desc "$_ba_nj")"
  fi
  if [ "$_ba_nj" = 1 ]; then _ba_dj=ON; else _ba_dj=OFF; fi
  have cmake || die "cmake not found (./setup.sh --deps installs it)"
  fetch aws-lc https://github.com/aws/aws-lc.git "$AWSLC_REF"
  LOG=$_ba_d/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  rm -rf "$_ba_d/build" "$_ba_d/aws-lc-install"
  info "cmake (Release, $(jitter_desc "$_ba_nj"), $(go version | cut -d' ' -f3), install to aws-lc/aws-lc-install)"
  step cmake -S "$_ba_d" -B "$_ba_d/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    -DDISABLE_CPU_JITTER_ENTROPY=$_ba_dj -DCMAKE_INSTALL_PREFIX="$_ba_d/aws-lc-install"
  info "build -j $JOBS"
  step cmake --build "$_ba_d/build" -j "$JOBS"
  step cmake --install "$_ba_d/build"
  AWSLC_BUILT=1
  info "built in $(since)"
}

build_s2n() {
  COMP=s2n-tls; _bs_d=$ROOT/s2n-tls
  hdr "s2n-tls ($S2N_REF)"
  if [ "$REBUILD" = 0 ] && [ "$AWSLC_BUILT" = 0 ] &&
     [ -x "$_bs_d/build/bin/s2nc" ] && [ -x "$_bs_d/build/bin/s2nd" ]; then
    info "already built (--rebuild to build again)"; return 0
  fi
  [ "$AWSLC_BUILT" = 0 ] || info "AWS-LC was rebuilt: rebuilding s2n-tls against it"
  [ -x "$BSSL_BIN" ] || die "s2n-tls needs AWS-LC: ./setup.sh aws-lc"
  have cmake || die "cmake not found (./setup.sh --deps installs it)"
  fetch s2n-tls https://github.com/aws/s2n-tls.git "$S2N_REF"
  LOG=$_bs_d/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  rm -rf "$_bs_d/build"
  # BUILD_TESTING stays on (s2n-tls's default): s2nc and s2nd are only defined with it
  info "cmake (Release, against aws-lc/aws-lc-install)"
  step cmake -S "$_bs_d" -B "$_bs_d/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$ROOT/aws-lc/aws-lc-install"
  info "build -j $JOBS (s2nc s2nd policy)"
  step cmake --build "$_bs_d/build" -j "$JOBS" --target s2nc s2nd policy
  info "built in $(since)"
}

# ---- rustls ----

RUSTLS_D=$ROOT/rustls-tools
RUSTLS_WC_D=$ROOT/rustls-wolfcrypt
RUSTUP=
# rustup (the toolchain in rustls-tools/rust-toolchain.toml runs through it):
# on PATH, Homebrew's keg-only one, ~/.cargo/bin, or set up with rustup-init
# (Alpine's package)
find_rustup() {
  for _fr_c in "$(command -v rustup 2>/dev/null)" "$(brew --prefix rustup 2>/dev/null)/bin/rustup" \
               "${CARGO_HOME:-$HOME/.cargo}/bin/rustup"; do
    if [ -n "$_fr_c" ] && [ -x "$_fr_c" ]; then RUSTUP=$_fr_c; return 0; fi
  done
  if have rustup-init; then
    rustup-init -y --default-toolchain none --no-modify-path --profile minimal >/dev/null 2>&1 &&
      [ -x "${CARGO_HOME:-$HOME/.cargo}/bin/rustup" ] && RUSTUP=${CARGO_HOME:-$HOME/.cargo}/bin/rustup && return 0
  fi
  return 1
}
rust_toolchain() { sed -n 's/^channel *= *"\(.*\)"/\1/p' "$RUSTLS_D/rust-toolchain.toml"; }

# rustls-wolfcrypt-provider (git only) at RUSTLS_WOLFCRYPT_REF, patched to
# build a given wolfSSL with given flags (and a bindgen that reads current
# libclang), and a clean export of the wolfSSL source this project builds
# (wolfssl/) for it
fetch_rustls_wolfcrypt() {
  _fw_p=$RUSTLS_D/providers/wolfcrypt/wolfcrypt-rs-build.patch
  if [ ! -d "$RUSTLS_WC_D/.git" ]; then
    info "fetching rustls-wolfcrypt-provider ($RUSTLS_WOLFCRYPT_REF)"
    step git clone --quiet https://github.com/wolfSSL/rustls-wolfcrypt-provider.git "$RUSTLS_WC_D"
  fi
  # (again whenever the patch changes; the applied copy is kept in .git)
  if [ "$(git -C "$RUSTLS_WC_D" rev-parse HEAD)" != "$RUSTLS_WOLFCRYPT_REF" ] ||
     ! cmp -s "$_fw_p" "$RUSTLS_WC_D/.git/pqc-applied.patch"; then
    step git -C "$RUSTLS_WC_D" checkout --quiet --force "$RUSTLS_WOLFCRYPT_REF"
    step git -C "$RUSTLS_WC_D" apply "$_fw_p"
    cp "$_fw_p" "$RUSTLS_WC_D/.git/pqc-applied.patch"
  fi
  [ -d "$ROOT/wolfssl/.git" ] || die "rustls wolfcrypt provider: it builds this project's wolfSSL source: ./setup.sh wolfssl first"
  _fw_v=$(git -C "$ROOT/wolfssl" rev-parse HEAD)
  if [ "$(cat "$RUSTLS_WC_D/wolfssl-src/.pqc-rev" 2>/dev/null)" != "$_fw_v" ]; then
    rm -rf "$RUSTLS_WC_D/wolfssl-src"; mkdir -p "$RUSTLS_WC_D/wolfssl-src"
    git -C "$ROOT/wolfssl" archive --format=tar HEAD | tar -x -C "$RUSTLS_WC_D/wolfssl-src" ||
      die "rustls wolfcrypt provider: exporting the wolfSSL source failed"
    echo "$_fw_v" > "$RUSTLS_WC_D/wolfssl-src/.pqc-rev"
    # the provider's wolfSSL was built from the old source: build it all again
    rm -rf "$RUSTLS_D/target/wolfcrypt"
  fi
}

# crate versions for a provider's package in its lock file -> "rustls 0.23.45,
# aws-lc-rs 1.18.1, ...": the version the package depends on where the lock
# has several (it then names it: "p256 0.14.0"), else the only one
rustls_versions() { # LOCKFILE PACKAGE CRATE...
  _rv_lock=$1; _rv_pkg=$2; shift 2
  awk -v pkg="$_rv_pkg" -v crates="$*" '
    $1 == "name" { name = $3; gsub(/"/, "", name); getline; v = $3; gsub(/"/, "", v)
                   if (!(name in first)) first[name] = v; deps = 0; next }
    $1 == "dependencies" && name == pkg { deps = 1; next }
    deps && /^]/ { deps = 0 }
    deps { d = $0; gsub(/[",]/, "", d); split(d, a, " "); if (a[2] != "") pin[a[1]] = a[2] }
    END { n = split(crates, cs, " ")
          for (i = 1; i <= n; i++) { c = cs[i]; v = (c in pin) ? pin[c] : first[c]
                                     if (v != "") out = out (out == "" ? "" : ", ") c " " v }
          print out }' "$_rv_lock"
}

# AWS-LC entropy of a statically linked binary (CPU Jitter Entropy: jent_*)
binary_jitter() { nm "$1" 2>/dev/null | grep -q 'jent_' && echo 1 || echo 0; }

# set when a rustls provider's hsloop library was built or rebuilt
RUSTLS_BUILT=
build_rustls() { # PROVIDER...
  COMP=rustls
  hdr "rustls ($(echo "$@"))"
  mkdir -p "$RUSTLS_D/bin"
  LOG=$RUSTLS_D/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  info "toolchain $(rust_toolchain) (rustup toolchain install)"
  # named explicitly: older rustup (Debian/Ubuntu packages) won't take it from rust-toolchain.toml
  ( cd "$RUSTLS_D" && "$RUSTUP" toolchain install --profile minimal "$(rust_toolchain)" >>"$LOG" 2>&1 ) ||
    die "rustls: installing the Rust toolchain failed (log: rustls-tools/pqc-setup.log)"
  # the pinned toolchain's cargo and rustc first on PATH (build scripts run
  # cargo and rustc too)
  _br_cargo=$("$RUSTUP" which --toolchain "$(rust_toolchain)" cargo 2>>"$LOG") ||
    die "rustls: no cargo in toolchain $(rust_toolchain) (log: rustls-tools/pqc-setup.log)"
  PATH=$(dirname "$_br_cargo"):$PATH; export PATH
  mkdir -p "$RUSTLS_D/target"
  # macOS: build for this OS, not the (possibly newer) SDK's version
  if [ "$(uname -s)" = Darwin ] && [ -z "${MACOSX_DEPLOYMENT_TARGET:-}" ]; then
    MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | cut -d. -f1-2); export MACOSX_DEPLOYMENT_TARGET
  fi
  # AWS-LC inside aws-lc-rs follows --awslc-(no-)jitter, else the AWS-LC build here
  _br_nj=${AWSLC_NO_JITTER:-$(awslc_built_no_jitter)}; _br_nj=${_br_nj:-0}
  for _br_p in "$@"; do
    case " $RUSTLS_PROVIDERS_ALL aws-lc-rs-fips " in *" $_br_p "*) ;; *) die "unknown rustls provider $_br_p (known: $RUSTLS_PROVIDERS_ALL)" ;; esac
    _br_t=$RUSTLS_D/target/$_br_p
    if [ "$REBUILD" = 1 ]; then rm -rf "$_br_t"; fi
    set --
    case $_br_p in
      wolfcrypt)
        fetch_rustls_wolfcrypt
        _br_dir=$RUSTLS_D/providers/wolfcrypt; _br_lock=$_br_dir/Cargo.lock
        _br_env="WOLFCRYPT_RS_WOLFSSL_SRC=$RUSTLS_WC_D/wolfssl-src"
        _br_cfg="--enable-all-crypto --disable-shared --enable-sp --enable-sp-asm${WOLF_ASM:+ $WOLF_ASM}"
        # musl (Alpine) links programs statically by default, and a static
        # build script (bindgen) can't load libclang
        _br_rf=; case $(rustc -vV 2>/dev/null | sed -n 's/^host: //p') in *-musl) _br_rf="-C target-feature=-crt-static" ;; esac ;;
      aws-lc-rs-fips)
        _br_dir=$RUSTLS_D; _br_lock=$RUSTLS_D/Cargo.lock; set -- -p pqc-rustls-aws-lc-rs --features fips
        _br_env= ; _br_cfg= ; _br_rf= ;;
      *)
        _br_dir=$RUSTLS_D; _br_lock=$RUSTLS_D/Cargo.lock; set -- -p "pqc-rustls-$_br_p"
        _br_env= ; _br_cfg= ; _br_rf= ;;
    esac
    _br_nje=; [ "$_br_p" = aws-lc-rs ] && [ "$_br_nj" = 1 ] && _br_nje=1
    info "$_br_p: cargo build --release$( [ -n "$_br_nje" ] && printf ' (AWS-LC without CPU jitter)')"
    _br_old=$(ls -l "$_br_t/release/libhsloop_rustls.a" 2>/dev/null)
    # the hsloop library (and the native libraries it needs), then pqc-rustls
    ( cd "$_br_dir" && env ${_br_env:+"$_br_env"} ${_br_rf:+"RUSTFLAGS=$_br_rf"} WOLFCRYPT_RS_CONFIGURE="$_br_cfg" \
        AWS_LC_SYS_NO_JITTER_ENTROPY="${_br_nje:-0}" \
        cargo rustc --release --locked "$@" --lib --target-dir "$_br_t" \
          -- --print native-static-libs ) > "$_br_t.log" 2>&1 ||
      { cat "$_br_t.log" >> "$LOG"; tail -n 30 "$_br_t.log" >&2; die "rustls $_br_p: build failed (log: rustls-tools/pqc-setup.log)"; }
    _br_nl=$(sed -n 's/^.*native-static-libs: *//p' "$_br_t.log" | tail -n 1)
    [ -n "$_br_nl" ] && printf '%s\n' "$_br_nl" > "$_br_t/native-static-libs"
    ( cd "$_br_dir" && env ${_br_env:+"$_br_env"} ${_br_rf:+"RUSTFLAGS=$_br_rf"} WOLFCRYPT_RS_CONFIGURE="$_br_cfg" \
        AWS_LC_SYS_NO_JITTER_ENTROPY="${_br_nje:-0}" \
        cargo build --release --locked "$@" --bins --target-dir "$_br_t" ) >> "$_br_t.log" 2>&1 ||
      { cat "$_br_t.log" >> "$LOG"; tail -n 30 "$_br_t.log" >&2; die "rustls $_br_p: build failed (log: rustls-tools/pqc-setup.log)"; }
    cat "$_br_t.log" >> "$LOG"; rm -f "$_br_t.log"
    [ "$(ls -l "$_br_t/release/libhsloop_rustls.a" 2>/dev/null)" = "$_br_old" ] || RUSTLS_BUILT="$RUSTLS_BUILT $_br_p"
    cp "$_br_t/release/pqc-rustls" "$RUSTLS_D/bin/pqc-rustls-$_br_p" || die "rustls $_br_p: no pqc-rustls built"
    # macOS: aws-lc-fips-sys builds the FIPS module as a shared library (static
    # only on Linux); it goes next to the binaries, found through the rpath
    if [ "$_br_p" = aws-lc-rs-fips ] && [ "$(uname -s)" = Darwin ]; then
      # the library the binary links (an older build tree may hold other versions)
      _br_dn=$(otool -L "$RUSTLS_D/bin/pqc-rustls-$_br_p" | sed -n 's|^[[:space:]]*@rpath/\(libaws_lc_fips_[^ ]*\.dylib\).*|\1|p')
      _br_dl=$( [ -n "$_br_dn" ] && find "$_br_t/release/build" -name "$_br_dn" 2>/dev/null | head -n 1)
      [ -n "$_br_dl" ] || die "rustls $_br_p: no AWS-LC FIPS library built"
      cp "$_br_dl" "$RUSTLS_D/bin/" &&
        install_name_tool -add_rpath @executable_path "$RUSTLS_D/bin/pqc-rustls-$_br_p" 2>>"$LOG" &&
        codesign --force -s - "$RUSTLS_D/bin/pqc-rustls-$_br_p" 2>>"$LOG" ||
        die "rustls $_br_p: can't install the AWS-LC FIPS library (log: rustls-tools/pqc-setup.log)"
    fi
    if [ "$_br_p" = aws-lc-rs-fips ] && ! "$RUSTLS_D/bin/pqc-rustls-$_br_p" caps 2>>"$LOG" | grep -qx 'fips yes'; then
      die "rustls $_br_p: the provider isn't in FIPS mode (pqc-rustls caps; log: rustls-tools/pqc-setup.log)"
    fi
    # what pqcbench.sh records: crate versions, and the AWS-LC inside aws-lc-rs
    _br_pkg=pqc-rustls-${_br_p%-fips}
    case $_br_p in
      aws-lc-rs*)
        _br_sys=aws-lc-sys; [ "$_br_p" = aws-lc-rs-fips ] && _br_sys=aws-lc-fips-sys
        _br_v=$(rustls_versions "$_br_lock" "$_br_pkg" rustls aws-lc-rs "$_br_sys")
        _br_s=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/"$_br_sys-$(rustls_versions "$_br_lock" "$_br_pkg" "$_br_sys" | cut -d' ' -f2)" 2>/dev/null | head -n 1)
        _br_a=$(sed -n 's/^#define AWSLC_VERSION_NUMBER_STRING "\(.*\)"/\1/p' "$_br_s/aws-lc/include/openssl/base.h" 2>/dev/null)
        [ -n "$_br_a" ] && _br_v="$_br_v (AWS-LC $_br_a$( [ "$_br_p" = aws-lc-rs-fips ] && printf ' FIPS module'))" ;;
      ring)       _br_v=$(rustls_versions "$_br_lock" "$_br_pkg" rustls ring) ;;
      # (this project's providers from crates.io, and the crates they use)
      graviola-pq) _br_v=$(rustls_versions "$_br_lock" rustls-provider-graviola-pq rustls-provider-graviola-pq rustls graviola) ;;
      graviola)   _br_v=$(rustls_versions "$_br_lock" "$_br_pkg" rustls rustls-graviola graviola) ;;
      rustcrypto) _br_v=$(rustls_versions "$_br_lock" "$_br_pkg" rustls rustls-rustcrypto) ;;
      rustcrypto-pq) _br_v=$(rustls_versions "$_br_lock" rustls-provider-rustcrypto-pq rustls-provider-rustcrypto-pq rustls ml-kem ml-dsa p256 p384 x25519-dalek ed25519-dalek rsa aes-gcm) ;;
      libcrux-pq) _br_v=$(rustls_versions "$_br_lock" rustls-provider-libcrux-pq rustls-provider-libcrux-pq rustls libcrux-ml-kem libcrux-ml-dsa libcrux-p256 libcrux-p384 libcrux-curve25519 libcrux-ed25519 libcrux-rsa libcrux-aes) ;;
      wolfcrypt)  _br_v="$(rustls_versions "$_br_lock" "$_br_pkg" rustls), rustls-wolfcrypt-provider $(git -C "$RUSTLS_WC_D" rev-parse --short HEAD), wolfSSL $(git -C "$ROOT/wolfssl" describe --tags --always 2>/dev/null) (optimized)" ;;
    esac
    printf '%s\n' "$_br_v" > "$RUSTLS_D/bin/pqc-rustls-$_br_p.versions"
    # (binary_jitter 1 = has CPU jitter, _br_nj 1 = wants none: equal = mismatch)
    if [ "$_br_p" = aws-lc-rs ] && [ "$(binary_jitter "$RUSTLS_D/bin/pqc-rustls-$_br_p")" = "$_br_nj" ]; then
      warn "rustls aws-lc-rs: the AWS-LC entropy build didn't follow --awslc-(no-)jitter; try ./setup.sh --rebuild rustls"
    fi
  done
  info "built in $(since): rustls-tools/bin/pqc-rustls-<provider>"
}

# ---- FIPS builds ----

# openssl-fips.cnf: FIPS mode for the OpenSSL built here. pqcbench.sh --fips
# uses it (with OPENSSL_MODULES pointing at the provider's directory).
write_openssl_fips_cnf() {
  cat > "$OSSLF_CNF" <<EOF
# OpenSSL configuration for FIPS mode, written by setup.sh: the FIPS provider
# from openssl-fips/ ($OPENSSL_FIPS_REF) plus the base provider (encoders and
# decoders), with approved algorithms only (fips=yes). Use it as
#   OPENSSL_CONF=$OSSLF_CNF \\
#   OPENSSL_MODULES=$OSSLF_MODDIR openssl ...
# config_diagnostics: a provider that fails to load (or a self-test that
# fails) stops the program instead of leaving it without FIPS mode.
config_diagnostics = 1
openssl_conf = openssl_init

.include $OSSLF_I/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
EOF
}
# version of the FIPS provider the OpenSSL built here loads with
# openssl-fips.cnf (empty if it doesn't load)
openssl_fips_version() {
  { [ -x "$OSSL_BIN" ] && [ -f "$OSSLF_CNF" ]; } || return 0
  OPENSSL_CONF=$OSSLF_CNF OPENSSL_MODULES=$OSSLF_MODDIR "$OSSL_BIN" list -providers 2>/dev/null |
    awk '/^  [^ ]/ { p = $1 } p == "fips" && $1 == "version:" { v = $2 }
         p == "fips" && $1 == "status:" { s = $2 } END { if (s == "active") print v }'
}

build_openssl_fips() {
  COMP=openssl-fips; _bf_d=$ROOT/openssl-fips
  hdr "OpenSSL FIPS provider ($OPENSSL_FIPS_REF)"
  [ -x "$OSSL_BIN" ] || die "openssl-fips: the FIPS provider is loaded by the OpenSSL built here: ./setup.sh openssl"
  if [ "$REBUILD" = 0 ] && [ -f "$OSSLF_MODDIR/fips.$DSO_EXT" ] && [ -f "$OSSLF_I/ssl/fipsmodule.cnf" ]; then
    write_openssl_fips_cnf
    _bf_v=$(openssl_fips_version)
    [ -n "$_bf_v" ] || die "openssl-fips: $("$OSSL_BIN" version | cut -d' ' -f1-2) doesn't load the FIPS provider (try --rebuild)"
    info "already built: FIPS provider $_bf_v (--rebuild to build again)"; return 0
  fi
  fetch openssl-fips https://github.com/openssl/openssl.git "$OPENSSL_FIPS_REF"
  LOG=$_bf_d/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  if [ -f "$_bf_d/Makefile" ]; then step make -C "$_bf_d" distclean; fi
  rm -rf "$OSSLF_I"
  # the same options as the main OpenSSL build (the FIPS module has its own
  # copy of the EC code, so enable-ec_nistp_64_gcc_128 matters here too)
  info "configure (enable-fips, static, enable-ec_nistp_64_gcc_128, prefix openssl-fips/openssl-fips-install)"
  step in_dir "$_bf_d" ./Configure enable-fips --prefix="$OSSLF_I" \
    --openssldir="$OSSLF_I/ssl" --libdir=lib no-shared no-tests no-docs \
    enable-ec_nistp_64_gcc_128
  info "make -j $JOBS"
  step make -C "$_bf_d" -j "$JOBS"
  # the provider module, and the fipsmodule.cnf that `openssl fipsinstall`
  # wrote after running the module's self-tests (it holds the module's MAC)
  step make -C "$_bf_d" install_fips
  write_openssl_fips_cnf
  _bf_v=$(openssl_fips_version)
  [ -n "$_bf_v" ] || die "openssl-fips: $("$OSSL_BIN" version | cut -d' ' -f1-2) doesn't load the FIPS provider with $OSSLF_CNF"
  info "built in $(since): FIPS provider $_bf_v, loaded by $("$OSSL_BIN" version | cut -d' ' -f1-2)"
}

# "wolfCrypt FIPS v7.0.0 (wolfssl-5.9.4-gplv3-fips-ready.zip)" from the
# configured wolfssl-fips tree
wolfssl_fips_desc() {
  _wd_o=$WOLFF_D/wolfssl/options.h
  _wd_v=$(awk '$1 == "#define" && $2 ~ /^HAVE_FIPS_VERSION_(MAJOR|MINOR|PATCH)$/ { v[$2] = $3 }
    END { if (v["HAVE_FIPS_VERSION_MAJOR"] != "")
            printf "v%s.%s.%s", v["HAVE_FIPS_VERSION_MAJOR"], v["HAVE_FIPS_VERSION_MINOR"] + 0, v["HAVE_FIPS_VERSION_PATCH"] + 0 }' "$_wd_o" 2>/dev/null)
  echo "wolfCrypt FIPS ${_wd_v:-version unknown} ($(cat "$WOLFF_D/$WOLFF_ORIGIN" 2>/dev/null || echo "origin unknown"))"
}

build_wolfssl_fips() {
  COMP=wolfssl-fips; _bw_d=$WOLFF_D
  hdr "wolfssl-fips (FIPS Ready)"
  if [ "$REBUILD" = 0 ] && [ -f "$WOLFF_I/lib/libwolfssl.$DSO_EXT" ] && [ -f "$_bw_d/wolfssl/options.h" ] &&
     [ -x "$_bw_d/examples/client/client" ] && [ -x "$_bw_d/examples/server/server" ]; then
    if configured_with "$_bw_d" "$WOLF_FIPS_FLAGS"; then
      info "already built: $(wolfssl_fips_desc) (--rebuild to build again)"; return 0
    fi
    info "built without some of today's configure options: building again"
  fi
  fetch_wolfssl_fips
  LOG=$_bw_d/pqc-setup.log; : > "$LOG"; START=$(date +%s)
  if [ ! -x "$_bw_d/configure" ]; then info "autogen.sh"; step in_dir "$_bw_d" ./autogen.sh; fi
  if [ -f "$_bw_d/Makefile" ]; then step make -C "$_bw_d" distclean; fi
  rm -rf "$WOLFF_I"
  [ -n "$WOLF_ASM" ] || warn "no wolfSSL assembly option for $(uname -m): building without --enable-armasm/--enable-intelasm"
  # The bundle ships a pre-generated configure whose config.guess (2018) takes
  # Apple silicon for 32-bit ARM, and --enable-armasm then adds -mfpu/-marm
  # flags clang rejects: name the platform instead
  _bw_b=
  if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then _bw_b="--build=aarch64-apple-darwin$(uname -r)"; fi
  info "configure ($(echo $WOLF_FIPS_FLAGS $WOLF_ASM $_bw_b), prefix wolfssl-fips/wolfssl-fips-install)"
  # shellcheck disable=SC2086
  step in_dir "$_bw_d" ./configure $WOLF_FIPS_FLAGS $WOLF_ASM $_bw_b --prefix="$WOLFF_I"
  info "make -j $JOBS"
  step make -C "$_bw_d" -j "$JOBS"
  # the module checks an HMAC of its own code at start-up: fips-hash.sh puts
  # the value this build computes into fips_test.c, then the library is rebuilt
  info "FIPS integrity hash (fips-hash.sh), make again"
  step in_dir "$_bw_d" sh ./fips-hash.sh
  step make -C "$_bw_d" -j "$JOBS"
  step make -C "$_bw_d" install
  info "wolfCrypt self-test (testwolfcrypt, includes the FIPS integrity check)"
  step in_dir "$_bw_d" ./wolfcrypt/test/testwolfcrypt
  info "built in $(since): $(wolfssl_fips_desc)"
}

# set when this run (re)builds AWS-LC FIPS: s2n-tls-fips is rebuilt against it
AWSLCF_BUILT=0
build_awslc_fips() {
  COMP=aws-lc-fips; _bx_d=$ROOT/aws-lc
  hdr "AWS-LC FIPS ($AWSLC_REF)"
  if [ "$REBUILD" = 0 ] && [ -x "$BSSLF_BIN" ]; then
    info "already built: FIPS_mode() = $("$BSSLF_BIN" isfips 2>/dev/null) (--rebuild to build again)"; return 0
  fi
  have cmake || die "cmake not found (./setup.sh --deps installs it)"
  fetch aws-lc https://github.com/aws/aws-lc.git "$AWSLC_REF"
  LOG=$_bx_d/pqc-setup-fips.log; : > "$LOG"; START=$(date +%s)
  rm -rf "$_bx_d/build-fips" "$AWSLCF_I"
  # AWS-LC builds a static FIPS module on Linux only; elsewhere libcrypto is
  # shared. CPU-jitter entropy can't be turned off in a FIPS build.
  if [ "$(uname -s)" = Linux ]; then _bx_sh=OFF; _bx_l=static; else _bx_sh=ON; _bx_l=shared; fi
  info "cmake (Release, FIPS, $_bx_l, CPU-jitter entropy, $(go version | cut -d' ' -f3), install to aws-lc/aws-lc-fips-install)"
  step cmake -S "$_bx_d" -B "$_bx_d/build-fips" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    -DFIPS=1 -DBUILD_SHARED_LIBS=$_bx_sh -DCMAKE_INSTALL_PREFIX="$AWSLCF_I" \
    -DCMAKE_INSTALL_RPATH="$AWSLCF_I/lib"
  info "build -j $JOBS"
  step cmake --build "$_bx_d/build-fips" -j "$JOBS"
  step cmake --install "$_bx_d/build-fips"
  # macOS: installing rewrites the libraries' and bssl's rpaths, which voids
  # their code signatures (the kernel then kills bssl at start). Sign them
  # again (ad hoc): the FIPS module's integrity hash covers its code and
  # constants, which neither step touches.
  if [ "$(uname -s)" = Darwin ]; then
    for _bx_f in "$AWSLCF_I"/lib/*.dylib "$AWSLCF_I"/bin/bssl "$AWSLCF_I"/bin/openssl; do
      [ -f "$_bx_f" ] && [ ! -L "$_bx_f" ] && step codesign --force -s - "$_bx_f"
    done
  fi
  [ "$("$BSSLF_BIN" isfips 2>>"$LOG")" = 1 ] ||
    die "aws-lc-fips: bssl isfips doesn't report FIPS mode (log: aws-lc/pqc-setup-fips.log)"
  AWSLCF_BUILT=1
  info "built in $(since): $_bx_l libcrypto, FIPS_mode() = 1"
}

build_s2n_fips() {
  COMP=s2n-tls-fips; _bs_d=$ROOT/s2n-tls
  hdr "s2n-tls FIPS ($S2N_REF, against AWS-LC FIPS)"
  if [ "$REBUILD" = 0 ] && [ "$AWSLCF_BUILT" = 0 ] &&
     [ -x "$S2NF_B/bin/s2nc" ] && [ -x "$S2NF_B/bin/s2nd" ]; then
    info "already built (--rebuild to build again)"; return 0
  fi
  [ "$AWSLCF_BUILT" = 0 ] || info "AWS-LC FIPS was rebuilt: rebuilding s2n-tls-fips against it"
  [ -x "$BSSLF_BIN" ] || die "s2n-tls-fips needs AWS-LC FIPS: ./setup.sh aws-lc-fips"
  have cmake || die "cmake not found (./setup.sh --deps installs it)"
  fetch s2n-tls https://github.com/aws/s2n-tls.git "$S2N_REF"
  LOG=$_bs_d/pqc-setup-fips.log; : > "$LOG"; START=$(date +%s)
  rm -rf "$S2NF_B"
  info "cmake (Release, against aws-lc/aws-lc-fips-install, build dir s2n-tls/build-fips)"
  step cmake -S "$_bs_d" -B "$S2NF_B" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$AWSLCF_I"
  info "build -j $JOBS (s2nc s2nd policy)"
  step cmake --build "$S2NF_B" -j "$JOBS" --target s2nc s2nd policy
  # s2n-tls takes FIPS mode from its libcrypto in s2n_init; with
  # --enter-fips-mode s2nc checks it before connecting (to a closed port here)
  "$S2NF_B/bin/s2nc" --enter-fips-mode 127.0.0.1 1 >> "$LOG" 2>&1
  grep -q '^s2nc entered FIPS mode' "$LOG" ||
    die "s2n-tls-fips: s2nc isn't in FIPS mode (log: s2n-tls/pqc-setup-fips.log)"
  info "built in $(since): s2nc enters FIPS mode"
}

# hsloop clients for pqcbench.sh --inproc. Each is rebuilt when missing, or
# older than its sources or the library it links, so a rebuilt library (e.g.
# --awslc-no-jitter, --rebuild openssl) never leaves a stale client. The FIPS
# builds get their own clients (hsloop-wolfssl-fips, hsloop-s2n-fips);
# hsloop-openssl serves both, as OpenSSL's FIPS mode is configuration.
HSLOOP_D=$ROOT/hsloop
hsloop_stale() { # BINARY DEPENDENCY...
  _hs_b=$1; shift
  [ "$REBUILD" = 1 ] && return 0
  [ -x "$_hs_b" ] || return 0
  for _hs_f in "$@"; do [ "$_hs_f" -nt "$_hs_b" ] && return 0; done
  return 1
}
hsloop_cc() { # NAME SOURCE CFLAGS LIBS  -> hsloop/bin/hsloop-NAME from hsloop/SOURCE.c
  _hc_out=$HSLOOP_D/bin/hsloop-$1
  # (no SOURCE: the adapter is inside LIBS, e.g. the rustls one)
  _hc_src=; [ -n "$2" ] && _hc_src=$HSLOOP_D/$2.c
  echo "$_hl_cc -O2 $3 $HSLOOP_D/hsloop.c $_hc_src -o $_hc_out $4" >> "$LOG"
  # shellcheck disable=SC2086
  if $_hl_cc -O2 $3 "$HSLOOP_D/hsloop.c" $_hc_src -o "$_hc_out" $4 >> "$LOG" 2>&1; then
    info "hsloop-$1 built"
  else
    rm -f "$_hc_out"
    if want hsloop; then tail -n 20 "$LOG" >&2; die "hsloop-$1 failed to compile (log: hsloop/pqc-setup.log)"; fi
    warn "hsloop-$1 failed to compile (log: hsloop/pqc-setup.log)"
  fi
}
build_hsloop() {
  COMP=hsloop
  # no sources: nothing to do
  [ -f "$HSLOOP_D/hsloop.c" ] || return 0
  _hl_cc=${CC:-cc}
  _hl_src="$HSLOOP_D/hsloop.c $HSLOOP_D/hsloop.h"
  _hl_o=$ROOT/openssl/openssl-install
  _hl_w=$ROOT/wolfssl
  _hl_s=$ROOT/s2n-tls
  _hl_a=$ROOT/aws-lc/aws-lc-install/lib/libcrypto.a
  _hl_wf=$WOLFF_I/lib/libwolfssl.$DSO_EXT
  # AWS-LC FIPS: static on Linux, shared elsewhere (build_awslc_fips)
  if [ -f "$AWSLCF_I/lib/libcrypto.a" ]; then _hl_af=$AWSLCF_I/lib/libcrypto.a; _hl_afl=$_hl_af
  else _hl_af=$AWSLCF_I/lib/libcrypto.$DSO_EXT; _hl_afl="-L$AWSLCF_I/lib -Wl,-rpath,$AWSLCF_I/lib -lcrypto"; fi
  _hl_todo=
  # shellcheck disable=SC2086
  { [ -f "$_hl_o/lib/libssl.a" ] && hsloop_stale "$HSLOOP_D/bin/hsloop-openssl" $_hl_src \
      "$HSLOOP_D/openssl.c" "$_hl_o/lib/libssl.a" "$_hl_o/lib/libcrypto.a" && _hl_todo="$_hl_todo openssl"; } || :
  # shellcheck disable=SC2086
  { [ -f "$_hl_w/src/.libs/libwolfssl.a" ] && hsloop_stale "$HSLOOP_D/bin/hsloop-wolfssl" $_hl_src \
      "$HSLOOP_D/wolfssl.c" "$_hl_w/src/.libs/libwolfssl.a" && _hl_todo="$_hl_todo wolfssl"; } || :
  # shellcheck disable=SC2086
  { [ -f "$_hl_s/build/lib/libs2n.a" ] && [ -f "$_hl_a" ] && hsloop_stale "$HSLOOP_D/bin/hsloop-s2n" $_hl_src \
      "$HSLOOP_D/s2n.c" "$_hl_s/build/lib/libs2n.a" "$_hl_a" && _hl_todo="$_hl_todo s2n"; } || :
  # shellcheck disable=SC2086
  { [ -f "$_hl_wf" ] && hsloop_stale "$HSLOOP_D/bin/hsloop-wolfssl-fips" $_hl_src \
      "$HSLOOP_D/wolfssl.c" "$_hl_wf" && _hl_todo="$_hl_todo wolfssl-fips"; } || :
  # shellcheck disable=SC2086
  { [ -f "$S2NF_B/lib/libs2n.a" ] && [ -f "$_hl_af" ] && hsloop_stale "$HSLOOP_D/bin/hsloop-s2n-fips" $_hl_src \
      "$HSLOOP_D/s2n.c" "$S2NF_B/lib/libs2n.a" "$_hl_af" && _hl_todo="$_hl_todo s2n-fips"; } || :
  # rustls: one client per provider built (the adapter is in its libhsloop_rustls.a)
  for _hl_p in $RUSTLS_PROVIDERS_ALL aws-lc-rs-fips; do
    _hl_r=$RUSTLS_D/target/$_hl_p/release/libhsloop_rustls.a
    # shellcheck disable=SC2086
    { [ -f "$_hl_r" ] && hsloop_stale "$HSLOOP_D/bin/hsloop-rustls-$_hl_p" $_hl_src "$_hl_r" &&
        _hl_todo="$_hl_todo rustls-$_hl_p"; } || :
  done
  if [ -z "$_hl_todo" ]; then
    if want hsloop; then hdr "hsloop"; info "up to date (--rebuild to build again)"; fi
    return 0
  fi
  hdr "hsloop (in-process handshake clients:$_hl_todo)"
  have "${_hl_cc%% *}" || die "C compiler '${_hl_cc%% *}' not found (set CC)"
  mkdir -p "$HSLOOP_D/bin"
  LOG=$HSLOOP_D/pqc-setup.log; : > "$LOG"
  for _hl_l in $_hl_todo; do
    case $_hl_l in
      openssl)
        hsloop_cc openssl openssl "-I$_hl_o/include" "$_hl_o/lib/libssl.a $_hl_o/lib/libcrypto.a -lpthread -ldl" ;;
      wolfssl)
        # a static wolfSSL doesn't carry its dependencies: they are in Libs.private
        _hl_wl="$_hl_w/src/.libs/libwolfssl.a $(sed -n 's/^Libs\.private: *//p' "$_hl_w/support/wolfssl.pc" 2>/dev/null)"
        if [ "$(uname -s)" = Darwin ]; then
          case " $_hl_wl " in *" -framework Security "*) ;; *) _hl_wl="$_hl_wl -framework CoreFoundation -framework Security" ;; esac
        fi
        hsloop_cc wolfssl wolfssl "-I$_hl_w" "$_hl_wl -lm -lpthread" ;;
      s2n)
        hsloop_cc s2n s2n "-I$_hl_s/api" "$_hl_s/build/lib/libs2n.a $_hl_a -lpthread -lm -ldl" ;;
      wolfssl-fips)
        hsloop_cc wolfssl-fips wolfssl "-I$WOLFF_I/include" \
          "-L$WOLFF_I/lib -Wl,-rpath,$WOLFF_I/lib -lwolfssl -lm -lpthread" ;;
      s2n-fips)
        hsloop_cc s2n-fips s2n "-I$_hl_s/api" "$S2NF_B/lib/libs2n.a $_hl_afl -lpthread -lm -ldl" ;;
      rustls-*)
        _hl_p=${_hl_l#rustls-}; _hl_r=$RUSTLS_D/target/$_hl_p
        # the native libraries rustc listed for the static library (-lSystem
        # is the macOS linker's own default)
        _hl_n=$(sed 's/-lSystem//g' "$_hl_r/native-static-libs" 2>/dev/null)
        # the wolfSSL inside the wolfcrypt provider uses Apple's trust store, as ours does
        if [ "$_hl_p" = wolfcrypt ] && [ "$(uname -s)" = Darwin ]; then
          _hl_n="$_hl_n -framework CoreFoundation -framework Security"
        fi
        if [ "$(uname -s)" = Darwin ] && [ -z "${MACOSX_DEPLOYMENT_TARGET:-}" ]; then
          MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | cut -d. -f1-2); export MACOSX_DEPLOYMENT_TARGET
        fi
        # macOS FIPS: the AWS-LC FIPS shared library build_rustls put next to pqc-rustls
        _hl_rp=; [ "$_hl_p" = aws-lc-rs-fips ] && [ "$(uname -s)" = Darwin ] &&
          _hl_rp="-L$RUSTLS_D/bin -Wl,-rpath,$RUSTLS_D/bin"
        hsloop_cc "rustls-$_hl_p" "" "" "$_hl_r/release/libhsloop_rustls.a $_hl_rp ${_hl_n:--lpthread -lm -ldl}" ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
ca_setup
if [ "$DO_DEPS" = 1 ]; then install_deps; ca_setup; fi
[ "$DEPS_ONLY" = 1 ] && exit 0

# AWS-LC is built when asked for, or for s2n-tls when it isn't built yet or
# its entropy configuration differs from --awslc-(no-)jitter. It needs Go:
# check now, before the other components take minutes to build.
AWSLC_MISMATCH=0
_m_have=$(awslc_built_no_jitter)
if [ -n "$AWSLC_NO_JITTER" ] && [ -x "$BSSL_BIN" ] && [ "$_m_have" != "$AWSLC_NO_JITTER" ]; then
  AWSLC_MISMATCH=1
fi
BUILD_AWSLC=0
if want aws-lc || { want s2n-tls && { [ ! -x "$BSSL_BIN" ] || [ "$AWSLC_MISMATCH" = 1 ]; }; }; then
  BUILD_AWSLC=1
fi
if [ "$BUILD_AWSLC" = 1 ] && { [ "$REBUILD" = 1 ] || [ ! -x "$BSSL_BIN" ] || [ "$AWSLC_MISMATCH" = 1 ]; } &&
   ! have go; then
  die "Go not found: AWS-LC needs it (./setup.sh --deps installs it, or install Go 1.20+)"
fi
# the FIPS builds: openssl-fips needs the OpenSSL that loads it, s2n-tls-fips
# needs AWS-LC FIPS
BUILD_OPENSSL=0; BUILD_AWSLCF=0
if want openssl || { want openssl-fips && [ ! -x "$OSSL_BIN" ]; }; then BUILD_OPENSSL=1; fi
if want aws-lc-fips || { want s2n-tls-fips && [ ! -x "$BSSLF_BIN" ]; }; then BUILD_AWSLCF=1; fi
if [ "$BUILD_AWSLCF" = 1 ] && { [ "$REBUILD" = 1 ] || [ ! -x "$BSSLF_BIN" ]; } && ! have go; then
  die "Go not found: AWS-LC FIPS needs it (./setup.sh --deps installs it, or install Go 1.20+)"
fi
if [ "$BUILD_AWSLCF" = 1 ] && [ "$AWSLC_NO_JITTER" = 1 ]; then
  info "--awslc-no-jitter applies to the non-FIPS AWS-LC only: the FIPS build keeps CPU-jitter entropy"
fi
# rustls needs rustup (a default build skips rustls without it). Its aws-lc-rs
# provider follows --awslc-(no-)jitter: an existing build that differs is
# rebuilt even when rustls isn't named.
BUILD_RUSTLS=0; RUSTLS_JITTER_FIX=0
if want rustls || want rustls-fips; then
  if find_rustup; then BUILD_RUSTLS=1
  elif [ "$RUSTLS_DEFAULT" = 1 ]; then warn "no Rust toolchain (rustup) found: skipping rustls (./setup.sh --deps installs rustup)"
  else die "rustls needs rustup (./setup.sh --deps installs it, or see https://rustup.rs)"; fi
fi
# (binary_jitter: 1 = has CPU jitter; AWSLC_NO_JITTER: 1 = wants none, so equal = mismatch)
if ! want rustls && [ -n "$AWSLC_NO_JITTER" ] && [ -x "$RUSTLS_D/bin/pqc-rustls-aws-lc-rs" ] &&
   [ "$(binary_jitter "$RUSTLS_D/bin/pqc-rustls-aws-lc-rs")" = "$AWSLC_NO_JITTER" ] && find_rustup; then
  RUSTLS_JITTER_FIX=1
fi
if want rustls-fips && [ "$BUILD_RUSTLS" = 1 ] && ! have go; then
  die "Go not found: rustls's aws-lc-rs FIPS provider (aws-lc-fips-sys) needs it (./setup.sh --deps installs it)"
fi

info "building in $ROOT with $JOBS jobs: $(echo $COMPONENTS)"
[ "$BUILD_OPENSSL" = 1 ] && build_openssl
want wolfssl && build_wolfssl wolfssl
want wolfssl-keylog && build_wolfssl wolfssl-keylog --enable-keylog-export \
  CFLAGS="${CFLAGS:+$CFLAGS }-DWOLFSSL_SSLKEYLOGFILE_USE_ENV"
[ "$BUILD_AWSLC" = 1 ] && build_awslc
# a rebuilt AWS-LC also rebuilds an existing s2n-tls (static libcrypto)
if want s2n-tls || { [ "$AWSLC_BUILT" = 1 ] && [ -x "$ROOT/s2n-tls/build/bin/s2nc" ]; }; then build_s2n; fi
want openssl-fips && build_openssl_fips
want wolfssl-fips && build_wolfssl_fips
[ "$BUILD_AWSLCF" = 1 ] && build_awslc_fips
# likewise a rebuilt AWS-LC FIPS rebuilds an existing s2n-tls-fips
if want s2n-tls-fips || { [ "$AWSLCF_BUILT" = 1 ] && [ -x "$S2NF_B/bin/s2nc" ]; }; then build_s2n_fips; fi
if [ "$BUILD_RUSTLS" = 1 ] && want rustls; then
  # shellcheck disable=SC2086
  build_rustls $RUSTLS_PROVIDERS
elif [ "$RUSTLS_JITTER_FIX" = 1 ]; then
  build_rustls aws-lc-rs
fi
[ "$BUILD_RUSTLS" = 1 ] && want rustls-fips && build_rustls aws-lc-rs-fips
# always: rebuilds only the hsloop clients that are missing or stale
build_hsloop

hdr "Ready"
[ -x "$OSSL_BIN" ] && info "OpenSSL:        $("$OSSL_BIN" version | cut -d' ' -f1-2)  openssl/openssl-install/bin/openssl"
for _m_d in wolfssl wolfssl-keylog; do
  [ -x "$ROOT/$_m_d/examples/client/client" ] &&
    info "$(printf '%-15s' "$_m_d:") $(git -C "$ROOT/$_m_d" describe --tags --always 2>/dev/null)  $_m_d/"
done
[ -x "$BSSL_BIN" ] && info "AWS-LC:         $(git -C "$ROOT/aws-lc" describe --tags --always 2>/dev/null)  aws-lc/aws-lc-install/bin/bssl ($(jitter_desc "$(awslc_built_no_jitter)"))"
[ -x "$ROOT/s2n-tls/build/bin/s2nc" ] &&
  info "s2n-tls:        $(git -C "$ROOT/s2n-tls" describe --tags --always 2>/dev/null)  s2n-tls/build/bin/s2nc, s2nd"
if [ -f "$OSSLF_CNF" ]; then
  _m_v=$(openssl_fips_version)
  info "OpenSSL FIPS:   provider ${_m_v:-NOT LOADING}  openssl-fips/openssl-fips-install (ssl/openssl-fips.cnf)"
fi
[ -f "$WOLFF_I/lib/libwolfssl.$DSO_EXT" ] && info "wolfssl-fips:   $(wolfssl_fips_desc)  wolfssl-fips/"
if [ -x "$BSSLF_BIN" ]; then
  if [ -f "$AWSLCF_I/lib/libcrypto.a" ]; then _m_l=static; else _m_l=shared; fi
  info "AWS-LC FIPS:    $(git -C "$ROOT/aws-lc" describe --tags --always 2>/dev/null)  aws-lc/aws-lc-fips-install/bin/bssl (FIPS_mode() = $("$BSSLF_BIN" isfips 2>/dev/null), $_m_l libcrypto)"
fi
[ -x "$S2NF_B/bin/s2nc" ] &&
  info "s2n-tls FIPS:   $(git -C "$ROOT/s2n-tls" describe --tags --always 2>/dev/null)  s2n-tls/build-fips/bin/s2nc, s2nd"
for _m_p in $RUSTLS_PROVIDERS_ALL aws-lc-rs-fips; do
  [ -x "$RUSTLS_D/bin/pqc-rustls-$_m_p" ] &&
    info "$(printf '%-15s' "rustls $_m_p:") $(cat "$RUSTLS_D/bin/pqc-rustls-$_m_p.versions" 2>/dev/null)  rustls-tools/bin/pqc-rustls-$_m_p"
done
_hl_bins=
for _hl_l in openssl wolfssl s2n wolfssl-fips s2n-fips; do
  [ -x "$HSLOOP_D/bin/hsloop-$_hl_l" ] && _hl_bins="${_hl_bins:+$_hl_bins, }hsloop-$_hl_l"
done
for _hl_l in $RUSTLS_PROVIDERS_ALL aws-lc-rs-fips; do
  [ -x "$HSLOOP_D/bin/hsloop-rustls-$_hl_l" ] && _hl_bins="${_hl_bins:+$_hl_bins, }hsloop-rustls-$_hl_l"
done
[ -n "$_hl_bins" ] && info "hsloop:         $_hl_bins  hsloop/bin/ (pqcbench.sh --inproc)"
info "pqcbench.sh finds all of these in $ROOT (the FIPS builds with --fips); run ./pqcbench.sh --help"
exit 0
