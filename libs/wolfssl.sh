# shellcheck shell=sh
# pqcbench.sh library: wolfSSL (example client/server, wolfCrypt benchmark,
# hsloop-wolfssl). Sourced by pqcbench.sh; see LIBRARY INTERFACE there.

LIBNAME_wolfssl=wolfSSL
LIBREQ_wolfssl=1

wolfssl_defaults() {
  if [ "$FIPS" = 1 ]; then _wd=wolfssl-fips; _wsfx=-fips; else _wd=wolfssl; _wsfx=; fi
  : "${WOLFSSL_DIR:=}"
  # Default: a configured wolfSSL tree in the project directory (next to
  # pqcbench.sh, or in the current directory): ./wolfssl, ./wolfssl-fips with --fips
  if [ -z "$WOLFSSL_DIR" ]; then
    for _cand in "$PQCB_DIR/$_wd" "./$_wd"; do
      if [ -f "$_cand/wolfssl/options.h" ]; then WOLFSSL_DIR=$_cand; break; fi
    done
  fi
  : "${WOLF_CLIENT:=${WOLFSSL_DIR:+$WOLFSSL_DIR/examples/client/client}}"
  : "${WOLF_SERVER:=${WOLFSSL_DIR:+$WOLFSSL_DIR/examples/server/server}}"
  : "${WOLF_BENCH:=${WOLFSSL_DIR:+$WOLFSSL_DIR/wolfcrypt/benchmark/benchmark}}"
  : "${HSLOOP_WOLFSSL:=${HSLOOP_DIR:+$HSLOOP_DIR/hsloop-wolfssl$_wsfx}}"
}

# ----------------------------------------------------------------------------
# GROUP TABLE
#   wolf_args_raw maps each group (OpenSSL names, see GROUP_ORDER) to the
#   wolfSSL example-client args that make it send that key share:
#     ""    -> no pinning flag (wolfSSL's default key shares)
#     SKIP  -> no clean way to pin this group on the wolfSSL client
#   Names match current wolfSSL (`examples/client/client -?`). Older releases
#   used e.g. P256_ML_KEM_768 for hybrids; edit here if a preflight fails. The
#   same --pqc value is passed to the wolfSSL server.
# ----------------------------------------------------------------------------
wolf_args_raw() {
  case $1 in
    X25519)             _war='-t' ;;
    P-256)              _war='-Y' ;;   # ECC key share only (secp256r1)
    P-384)              _war='SKIP' ;;
    MLKEM512)           _war='--pqc ML_KEM_512' ;;
    MLKEM768)           _war='--pqc ML_KEM_768' ;;
    MLKEM1024)          _war='--pqc ML_KEM_1024' ;;
    X25519MLKEM768)     _war='--pqc X25519MLKEM768' ;;
    SecP256r1MLKEM768)  _war='--pqc SecP256r1MLKEM768' ;;
    SecP384r1MLKEM1024) _war='--pqc SecP384r1MLKEM1024' ;;
    *)                  _war='UNKNOWN' ;;
  esac
  printf '%s\n' "$_war"
}

NO_PQC=0
wolf_args() {
  _wa=$(wolf_args_raw "$1")
  if [ "$NO_PQC" = 1 ]; then
    case $_wa in --pqc*) _wa=SKIP ;; esac
  fi
  printf '%s\n' "$_wa"
}

# Can this wolfSSL build use GROUP? A --pqc name its build lacks is rejected
# before the example client connects, so one run against a closed port (1)
# tells; cached per group. Call directly, not in $(...).
wolfssl_has_group() { # GROUP
  _wh_a=$(wolf_args_raw "$1")
  case $_wh_a in --pqc*) ;; *) return 0 ;; esac
  [ "$NO_PQC" = 1 ] && return 1
  _wh_v=WOLF_HAS_$(ptag "$1")
  eval "_wh_r=\${$_wh_v:-}"
  if [ -z "$_wh_r" ]; then
    # shellcheck disable=SC2086
    if $TO_CMD "$WOLF_CLIENT" -v 4 -h 127.0.0.1 -p 1 $_wh_a 2>&1 | grep -q 'invalid post-quantum KEM'; then
      _wh_r=no
    else
      _wh_r=yes
    fi
    eval "$_wh_v=\$_wh_r"
  fi
  [ "$_wh_r" = yes ]
}

# Prefer real binaries over libtool wrapper scripts (the wrapper is a shell
# script and would add its own startup time to every wolfSSL handshake).
unwrap_libtool() { # VARNAME
  eval "_ul_p=\${$1}"
  [ -f "$_ul_p" ] || return 0
  [ "$(head -n 1 "$_ul_p" 2>/dev/null | cut -c1-2)" = '#!' ] || return 0
  _ul_real="$(dirname "$_ul_p")/.libs/$(basename "$_ul_p")"
  if [ -x "$_ul_real" ]; then
    eval "$1=\$_ul_real"
    LD_LIBRARY_PATH="$WOLFSSL_DIR/src/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    DYLD_LIBRARY_PATH="$WOLFSSL_DIR/src/.libs${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    export LD_LIBRARY_PATH DYLD_LIBRARY_PATH
    info "using $_ul_real instead of libtool wrapper"
  else
    warn "$_ul_p is a libtool wrapper; timings include its overhead (build with --disable-shared to avoid)"
  fi
}

wolfssl_detect() {
  [ -n "$WOLFSSL_DIR" ] && WOLFSSL_DIR=$(cd "$WOLFSSL_DIR" 2>/dev/null && pwd)
  [ -n "$WOLF_CLIENT" ] && WOLF_CLIENT=$(abspath "$WOLF_CLIENT")
  [ -n "$WOLF_SERVER" ] && WOLF_SERVER=$(abspath "$WOLF_SERVER")
  [ -n "$WOLF_BENCH" ]  && WOLF_BENCH=$(abspath "$WOLF_BENCH")
  [ -n "$HSLOOP_WOLFSSL" ] && HSLOOP_WOLFSSL=$(abspath "$HSLOOP_WOLFSSL")
  # The wolfSSL example programs find their default files by walking up from
  # the current directory to the source tree (looking for certs/dh2048.pem)
  # and abort with "wolf root not found" otherwise, so pqcbench.sh runs
  # everything from there (RUN_DIR).
  if [ -z "$WOLFSSL_DIR" ] && [ -n "$WOLF_CLIENT" ]; then
    _fr=$(dirname "$WOLF_CLIENT")
    while [ -n "$_fr" ] && [ "$_fr" != / ]; do
      if [ -f "$_fr/certs/dh2048.pem" ]; then WOLFSSL_DIR=$_fr; break; fi
      _fr=$(dirname "$_fr")
    done
  fi
  RUN_DIR=$WOLFSSL_DIR
  # --fips: the wolfSSL tree must be a FIPS build (setup.sh --fips: wolfssl-fips/)
  WOLF_FIPS=
  [ "$FIPS" = 1 ] || return 0
  _wfo=${WOLFSSL_DIR:+$WOLFSSL_DIR/wolfssl/options.h}
  if [ -z "$_wfo" ] || ! grep -q '^#define HAVE_FIPS *$' "$_wfo" 2>/dev/null; then
    die "--fips: ${WOLFSSL_DIR:-the wolfSSL build} isn't a wolfSSL FIPS build (./setup.sh --fips builds wolfssl-fips/)"
  fi
  WOLF_FIPS=$(awk '$1 == "#define" && $2 ~ /^HAVE_FIPS_VERSION_(MAJOR|MINOR|PATCH)$/ { v[$2] = $3 }
    $1 == "#define" && $2 == "WOLFSSL_FIPS_READY" { r = " (FIPS Ready)" }
    END { printf "wolfCrypt FIPS v%s.%s.%s%s", v["HAVE_FIPS_VERSION_MAJOR"], v["HAVE_FIPS_VERSION_MINOR"] + 0,
          v["HAVE_FIPS_VERSION_PATCH"] + 0, r }' "$_wfo")
  [ -f "$WOLFSSL_DIR/.pqc-fips-source" ] && WOLF_FIPS="$WOLF_FIPS, from $(cat "$WOLFSSL_DIR/.pqc-fips-source")"
  return 0
}

wolfssl_prepare() {
  if [ -z "$WOLFSSL_DIR" ] && [ "$DO_HS" = 1 ]; then
    warn "WOLFSSL_DIR not set; wolfSSL examples may fail with 'wolf root not found'"
  fi
  if [ "$DO_HS" = 1 ]; then
    { [ -x "$WOLF_CLIENT" ] && [ -x "$WOLF_SERVER" ]; } \
      || die "wolfSSL example client/server not found. Set WOLFSSL_DIR (or WOLF_CLIENT/WOLF_SERVER)."
    unwrap_libtool WOLF_CLIENT
    unwrap_libtool WOLF_SERVER
    if ! "$WOLF_CLIENT" '-?' 2>&1 | grep -q -e '--pqc'; then
      warn "wolfSSL client has no --pqc option (built without ML-KEM?); PQ groups skipped for wolfSSL client"
      NO_PQC=1
    fi
  fi
  if [ "$DO_PRIM" = 1 ] && [ -n "$WOLF_BENCH" ]; then unwrap_libtool WOLF_BENCH; fi
}

wolfssl_label() { echo wolfSSL; }
wolfssl_env() {
  echo "wolfssl client: $WOLF_CLIENT"
  echo "wolfssl server: $WOLF_SERVER"
  echo "wolfcrypt bench: $WOLF_BENCH"
}
wolfssl_fips_env() { echo "fips wolfssl: $WOLF_FIPS; shared library"; }
wolfssl_fips_desc() { echo "$WOLF_FIPS"; }

wolfssl_speed() { # kem|mldsa
  hdr "Primitives ($_what): wolfCrypt benchmark"
  if [ -z "$WOLF_BENCH" ] || [ ! -x "$WOLF_BENCH" ]; then
    warn "wolfCrypt benchmark not found (set WOLFSSL_DIR or WOLF_BENCH); skipping"
    return 0
  fi
  _help=$("$WOLF_BENCH" -help 2>&1)
  # shellcheck disable=SC2020
  _tokens=$(printf '%s\n' "$_help" | tr -d '[]' | tr -s ' \t,' '\n\n\n' | grep -E '^-[a-z0-9_-]+$' | sort -u)
  has_flag() { printf '%s\n' "$_tokens" | grep -qx -e "$1"; }
  _flags=
  if [ "$1" = kem ]; then
    for _w in -ml-kem -mlkem -kyber;  do if has_flag "$_w"; then _flags="$_flags $_w"; break; fi; done
    for _w in -ecc-all -ecc;          do if has_flag "$_w"; then _flags="$_flags $_w"; break; fi; done
    for _w in -x25519 -curve25519;    do if has_flag "$_w"; then _flags="$_flags $_w"; break; fi; done
    for _w in -rsa -dh;               do if has_flag "$_w"; then _flags="$_flags $_w"; fi; done
  else
    for _w in -ml-dsa -mldsa -dilithium; do if has_flag "$_w"; then _flags="$_flags $_w"; break; fi; done
    for _w in -ecc-all -ecc;          do if has_flag "$_w"; then _flags="$_flags $_w"; break; fi; done
    for _w in -ed25519 -rsa;          do if has_flag "$_w"; then _flags="$_flags $_w"; fi; done
  fi
  if [ -z "$_flags" ]; then
    warn "couldn't detect algorithm flags from '$WOLF_BENCH -help'; running full benchmark"
  else
    info "wolfCrypt benchmark flags:$_flags"
  fi
  # shellcheck disable=SC2086
  "$WOLF_BENCH" $_flags 2>&1 | tee "$_pd/wolfcrypt-$1.txt" | sed 's/^/    /'
}

wolfssl_cli_skip() { # GROUP
  [ "$(wolf_args "$1")" = SKIP ] && echo "can't pin group on wolfSSL client"
  return 0
}
wolfssl_srv_skip() { :; }

wolfssl_server() { # GROUP PORT LOG KEYS
  _ws_group=$1; _ws_log=$3; _ws_keys=$4
  set -- -p "$2" -v 4 -i -g -c "$SRV_CERT" -k "$SRV_KEY"
  if [ -n "$SRV_CA" ]; then set -- "$@" -A "$SRV_CA" -F; else set -- "$@" -d; fi
  # (-b: every interface; the example server has no other address option)
  [ "$SERVER_ADDR" = 127.0.0.1 ] || set -- "$@" -b
  _ws_pqc=$(wolf_args "$_ws_group")
  # shellcheck disable=SC2086
  case $_ws_pqc in --pqc*) set -- "$@" $_ws_pqc ;; esac
  [ -n "$_ws_keys" ] || _ws_keys=${SSLKEYLOGFILE:-}
  SSLKEYLOGFILE=$_ws_keys "$WOLF_SERVER" "$@" </dev/null >>"$_ws_log" 2>&1 &
}
wolfssl_start_fail_hint() { # GROUP LOG
  if grep -q 'invalid post-quantum KEM' "$2" 2>/dev/null; then
    warn "  wolfSSL rejected --pqc $(wolf_args_raw "$1" | sed 's/^--pqc //'); pure ML-KEM needs --enable-tls-mlkem-standalone"
  fi
}

wolfssl_client() { # GROUP PORT [brief]
  _wc_group=$1
  set -- -h "$CONNECT_HOST" -p "$2" -v 4 -A "$CLI_CA" -g
  if [ -n "$CLI_CERT" ]; then set -- "$@" -c "$CLI_CERT" -k "$CLI_KEY"; else set -- "$@" -x; fi
  # shellcheck disable=SC2046,SC2086
  SSLKEYLOGFILE=$(cli_keylog_val) $TO_CMD "$WOLF_CLIENT" "$@" $(wolf_args "$_wc_group")
}

# preflight: why the wolfSSL client failed (empty: no wolfSSL-specific reason)
wolfssl_preflight_why() { # PREFLIGHT_LOG GROUP
  grep -q 'invalid post-quantum KEM' "$1" 2>/dev/null && echo "wolfSSL client build lacks this group"
  return 0
}
# a preflight failure that involves wolfSSL on a pure ML-KEM group
wolfssl_why_hint() { # GROUP WHY
  case $1 in
    MLKEM*) case $2 in *wolfSSL*|*wolfssl*) echo "$2 (build wolfSSL with --enable-tls-mlkem-standalone)"; return 0 ;; esac ;;
  esac
  echo "$2"
}

wolfssl_startup() { $TO_CMD "$WOLF_CLIENT" '-?' >/dev/null 2>&1; }

wolfssl_inproc_bin() { printf '%s\n' "$HSLOOP_WOLFSSL"; }

# wolfSSL writes TLS secrets only when built with --enable-keylog-export
WOLF_KEYLOG=0
wolfssl_keylogs() { [ "$WOLF_KEYLOG" = 1 ]; }
wolfssl_cap_setup() {
  if [ -n "$WOLFSSL_DIR" ] && grep -q "WOLFSSL_SSLKEYLOGFILE" "$WOLFSSL_DIR/wolfssl/options.h" 2>/dev/null; then
    WOLF_KEYLOG=1
  fi
  if [ "$WOLF_KEYLOG" = 1 ]; then
    warn "wolfSSL is built with --enable-keylog-export: it writes TLS secrets on every handshake (slower, and insecure outside testing)"
  else
    warn "wolfSSL has no key logging, so wolfSSL->wolfSSL captures can't be decrypted (build a separate wolfSSL with --enable-keylog-export for that)"
  fi
}

# ---- versions mode ----
vs_w_ver() { case $1 in 1.2) echo "-v 3" ;; 1.3) echo "-v 4" ;; any) echo "-v d" ;; esac; }
vs_w_cgroups() { case $1 in classical) echo "-t" ;; hybrid) echo "--pqc X25519MLKEM768" ;;
                            pq) echo "--pqc ML_KEM_1024" ;; esac; }
# wolfSSL's example server can only restrict its groups on TLS 1.3 (--force-curve);
# otherwise -t just pre-generates an X25519 key share
vs_w_sgroups() {
  case $1 in
    classical) if [ "$2" = 1.3 ]; then echo "--force-curve CURVE25519"; else echo "-t"; fi ;;
    *) echo "" ;;
  esac
}

wolfssl_vs_server() { # PORT LOG KEYS
  _wv_keys=$3; [ -n "$_wv_keys" ] || _wv_keys=${SSLKEYLOGFILE:-}
  _wv_b=; [ "$SERVER_ADDR" = 127.0.0.1 ] || _wv_b=-b
  # shellcheck disable=SC2046,SC2086
  SSLKEYLOGFILE=$_wv_keys "$WOLF_SERVER" -p "$1" $(vs_w_ver "$VS_SV") -i -d -g $_wv_b \
    -c "$VS_SCERT" -k "$VS_SKEY" $(vs_w_sgroups "$VS_SG" "$VS_SV") </dev/null >>"$2" 2>&1 &
}

wolfssl_vs_client() { # PORT [brief]
  # shellcheck disable=SC2046,SC2086
  SSLKEYLOGFILE=$(cli_keylog_val) $TO_CMD "$WOLF_CLIENT" -h "$CONNECT_HOST" -p "$1" \
    $(vs_w_ver "$VS_CV") -A "$VS_CA" -x -g $(vs_w_cgroups "$VS_CG")
}

# the example client's --pqc only sets the key share: all groups stay offered,
# so an ML-KEM-only client falls back instead of being refused
wolfssl_vs_expect() { # SCENARIO SERVER
  case $1 in
    pq-down12)       VS_EXPECT=1.2/classical
                     VS_NOTE="wolfSSL example client: --pqc only sets the key share; all groups stay offered, so it falls back" ;;
    pq-vs-classical) VS_EXPECT=1.3/classical
                     VS_NOTE="wolfSSL example client: --pqc only sets the key share; all groups stay offered, so it retries classically" ;;
  esac
}
