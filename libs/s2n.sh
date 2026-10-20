# shellcheck shell=sh
# pqcbench.sh library: s2n-tls (s2nc / s2nd, hsloop-s2n) and its libcrypto
# AWS-LC (bssl speed). Optional: left out when s2nc/s2nd aren't built, or with
# --no-s2n. Sourced by pqcbench.sh; see LIBRARY INTERFACE there.

LIBNAME_s2n=s2n-tls
LIBREQ_s2n=0

s2n_defaults() {
  if [ "$FIPS" = 1 ]; then _s2nb=build-fips; _awi=aws-lc-fips-install; _ssfx=-fips
  else _s2nb=build; _awi=aws-lc-install; _ssfx=; fi
  : "${S2N_DIR:=}"
  # Default: an s2n-tls tree with its CMake build in s2n-tls/build (build-fips
  # with --fips; next to pqcbench.sh, or in the current directory)
  if [ -z "$S2N_DIR" ]; then
    for _cand in "$PQCB_DIR/s2n-tls" ./s2n-tls; do
      if [ -x "$_cand/$_s2nb/bin/s2nc" ]; then S2N_DIR=$_cand; break; fi
    done
  fi
  : "${S2N_CLIENT:=${S2N_DIR:+$S2N_DIR/$_s2nb/bin/s2nc}}"
  : "${S2N_SERVER:=${S2N_DIR:+$S2N_DIR/$_s2nb/bin/s2nd}}"
  # AWS-LC's bssl tool (s2n-tls's libcrypto) for the primitive benchmarks
  : "${BSSL:=}"
  if [ -z "$BSSL" ]; then
    for _cand in "$PQCB_DIR/aws-lc/$_awi/bin/bssl" "./aws-lc/$_awi/bin/bssl"; do
      if [ -x "$_cand" ]; then BSSL=$_cand; break; fi
    done
  fi
  : "${HSLOOP_S2N:=${HSLOOP_DIR:+$HSLOOP_DIR/hsloop-s2n$_ssfx}}"

  # AWS-LC `bssl speed -filter` lists (comma-separated; "RSA" runs every key size)
  BSSL_SPEED_KEM="ML-KEM,Curve25519,EVP ECDH P-256,EVP ECDH P-384,RSA"
  BSSL_SPEED_MLDSA="MLDSA,ECDSA P-256,ECDSA P-384,Ed25519,RSA"
  # --fips: no X25519
  [ "$FIPS" = 1 ] && BSSL_SPEED_KEM="ML-KEM,EVP ECDH P-256,EVP ECDH P-384,RSA"
}

# ----------------------------------------------------------------------------
# s2n-tls POLICY TABLE
#   s2nc/s2nd have no group or version flags: everything comes from a named
#   security policy (-c; `s2n-tls/build/bin/policy NAME` prints one). An s2n
#   client sends one key share for its policy's first KEM group and one for
#   its first curve, so pinning a group takes a built-in policy that lists it
#   first and nothing else that would send a share. The s2n server takes any
#   supported key share the client sent.
#     SKIP        -> no built-in policy pins this group on the s2n client
#     UNSUPPORTED -> s2n-tls doesn't implement the group
#   s2n_cli_policy's second argument is the certificate chain (CERTK): ec, or
#   mldsa<level> for an ML-DSA chain (mldsa<CA>-<leaf> when the levels
#   differ). Accepting an ML-DSA chain, and signing with an ML-DSA client
#   certificate, also needs those ML-DSA signature schemes, which few of the
#   pinning policies offer: the ML-KEM-1024 ones offer ML-DSA-87 only.
#   --fips: only policies that pass s2n-tls's "FIPS 140-3 (2019)" rule (the
#   `policy` tool's "rules:" lines) and offer TLS 1.3; s2n-tls in FIPS mode
#   would accept the others too.
# ----------------------------------------------------------------------------
s2n_cli_policy() { # GROUP [CERTK]
  if [ "$FIPS" = 1 ]; then
    case $1:${2:-ec} in
      P-256:ec)              echo 20230317 ;;        # P-256 first, no KEM groups
      P-384:ec)              echo 20250414 ;;        # P-384 only
      MLKEM1024:ec)          echo 20260513 ;;        # ML-KEM-1024, plus a P-384 key share
      MLKEM1024:mldsa87)     echo cnsa_2 ;;          # ML-KEM-1024 only; ML-DSA-87 only
      X25519MLKEM768:ec)     echo default_fips ;;    # plus a P-256 key share
      X25519MLKEM768:mldsa*) echo test_all_fips ;;   # plus a P-256 key share
      MLKEM512:*|MLKEM768:*) echo UNSUPPORTED ;;
      X25519:*|P-256:*|P-384:*|MLKEM1024:*|SecP256r1MLKEM768:*|SecP384r1MLKEM1024:*) echo SKIP ;;
      *)                     echo UNKNOWN ;;
    esac
    return 0
  fi
  case $1:${2:-ec} in
    X25519:*)              echo test_all_tls13 ;;  # X25519 first, no KEM groups
    P-256:ec)              echo default_tls13 ;;   # P-256 first, no KEM groups
    P-384:ec)              echo 20250414 ;;        # P-384 only
    MLKEM1024:ec)          echo 20260513 ;;        # ML-KEM-1024, plus a P-384 key share
    MLKEM1024:mldsa87)     echo cnsa_2 ;;          # ML-KEM-1024 only; ML-DSA-87 only
    X25519MLKEM768:ec)     echo test_pq_only ;;    # X25519MLKEM768 first, no curves
    X25519MLKEM768:mldsa*) echo default_pq ;;      # plus a P-256 key share
    MLKEM512:*|MLKEM768:*) echo UNSUPPORTED ;;
    P-256:*|P-384:*|MLKEM1024:*|SecP256r1MLKEM768:*|SecP384r1MLKEM1024:*) echo SKIP ;;
    *)                     echo UNKNOWN ;;
  esac
}
# Classical groups get a policy without KEM groups: given one, the s2n server
# answers a client that merely lists a KEM group with a HelloRetryRequest.
# Both policies offer every ML-DSA signature scheme, so any --cert works.
# --fips: test_all_fips is the only FIPS policy with ML-DSA-44/65, and it has
# KEM groups, so the KEM-free 20230317 serves classical groups with an EC
# certificate (CERTK ec) and test_all_fips the rest.
s2n_srv_policy() { # GROUP
  if [ "$FIPS" = 1 ]; then
    case $1 in
      P-256|P-384)         if [ "$CERTK" = ec ]; then echo 20230317; else echo test_all_fips; fi ;;
      MLKEM1024|X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024) echo test_all_fips ;;
      X25519|MLKEM512|MLKEM768) echo UNSUPPORTED ;;
      *)                   echo UNKNOWN ;;
    esac
    return 0
  fi
  case $1 in
    X25519|P-256|P-384)    echo test_all_tls13 ;;
    MLKEM1024|X25519MLKEM768|SecP256r1MLKEM768|SecP384r1MLKEM1024) echo test_all ;;
    MLKEM512|MLKEM768)     echo UNSUPPORTED ;;
    *)                     echo UNKNOWN ;;
  esac
}

# AWS-LC entropy configuration of a statically linked binary, from its symbols:
# CPU Jitter Entropy (jent_*) is only linked in when AWS-LC uses it
awslc_entropy() { # BINARY
  if ! have nm; then echo "unknown (no nm)"; return 0; fi
  nm "$1" 2>/dev/null | awk '{ n = 1 } /jent_/ { j = 1 }
    END { print (!n ? "unknown (no symbols)" : j ? "CPU jitter (stock)" : "OS only (built without CPU jitter)") }'
}
# --fips: shared or static libcrypto in a binary (AWS-LC FIPS is shared on macOS)
libcrypto_linkage() { # BINARY
  if [ "$(uname -s)" = Darwin ]; then
    have otool || { echo unknown; return 0; }
    otool -L "$1" 2>/dev/null | grep -q 'libcrypto' && echo shared || echo static
  else
    have ldd || { echo unknown; return 0; }
    ldd "$1" 2>/dev/null | grep -q 'libcrypto' && echo shared || echo static
  fi
}

# the library takes part when both of its test programs are built
s2n_detect() {
  [ -n "$S2N_DIR" ]    && S2N_DIR=$(cd "$S2N_DIR" 2>/dev/null && pwd)
  [ -n "$S2N_CLIENT" ] && S2N_CLIENT=$(abspath "$S2N_CLIENT")
  [ -n "$S2N_SERVER" ] && S2N_SERVER=$(abspath "$S2N_SERVER")
  [ -n "$BSSL" ]       && BSSL=$(abspath "$BSSL")
  [ -n "$HSLOOP_S2N" ] && HSLOOP_S2N=$(abspath "$HSLOOP_S2N")
  if [ -x "$S2N_CLIENT" ] && [ -x "$S2N_SERVER" ]; then return 0; fi
  if [ -n "$S2N_CLIENT$S2N_SERVER" ]; then
    LIBNOTE_s2n="s2n-tls s2nc/s2nd not found ($S2N_CLIENT, $S2N_SERVER); leaving s2n-tls out"
    LIBNOTE_WARN_s2n=1
  else
    LIBNOTE_s2n="s2n-tls not found (build it in ./s2n-tls or set S2N_DIR); leaving s2n-tls out"
  fi
  return 1
}

S2N_REQ=; S2N_FIFO=; S2N_NOCERTS=; S2N_NOCERTS_DIR=; S2N_CLOSED_PORT=; S2N_VERSION=; S2N_LIBCRYPTO=
AWSLC_ENTROPY=
s2n_prepare() {
  # working files for s2nc/s2nd (see s2n_client): the HTTP request, an empty
  # trust store for AWS-LC's defaults, and the FIFO that keeps s2nc's stdin open
  S2N_REQ=$OUTDIR/tools/s2n/request.txt; S2N_FIFO=$OUTDIR/tools/s2n/stdin.fifo
  S2N_NOCERTS=$OUTDIR/tools/s2n/no-system-certs.pem; S2N_NOCERTS_DIR=$OUTDIR/tools/s2n/no-system-certs
  mkdir -p "$S2N_NOCERTS_DIR" || die "cannot create $OUTDIR/tools/s2n"
  printf 'GET / HTTP/1.0\r\n\r\n' > "$S2N_REQ"; : > "$S2N_NOCERTS"
  rm -f "$S2N_FIFO"; mkfifo "$S2N_FIFO" || die "mkfifo failed (s2nc's stdin needs a FIFO)"
  # a port nothing listens on: the s2n startup baseline ends at a refused connect
  S2N_CLOSED_PORT=$((BASE_PORT - 1)); _cp=0
  while [ "$PORT_TOOL" != none ] && [ $_cp -lt 20 ] && port_listening "$S2N_CLOSED_PORT"; do
    S2N_CLOSED_PORT=$((S2N_CLOSED_PORT - 1)); _cp=$((_cp + 1))
  done
  [ -n "$S2N_DIR" ] && S2N_VERSION=$(git -C "$S2N_DIR" describe --tags --always 2>/dev/null)
  # --enter-fips-mode: s2nc stops unless s2n_init found its libcrypto in FIPS mode
  _s2n_fm=; [ "$FIPS" = 1 ] && _s2n_fm=--enter-fips-mode
  # shellcheck disable=SC2086
  _s2n_probe=$(SSL_CERT_FILE=$S2N_NOCERTS SSL_CERT_DIR=$S2N_NOCERTS_DIR \
          $TO_CMD "$S2N_CLIENT" $_s2n_fm 127.0.0.1 "$S2N_CLOSED_PORT" 2>&1)
  S2N_LIBCRYPTO=$(printf '%s\n' "$_s2n_probe" | sed -n 's/^libcrypto: //p')
  S2N_VERSION="${S2N_VERSION:-unknown version}${S2N_LIBCRYPTO:+, libcrypto $S2N_LIBCRYPTO}"
  if [ "$FIPS" = 1 ] && ! printf '%s\n' "$_s2n_probe" | grep -q '^s2nc entered FIPS mode'; then
    die "--fips: $S2N_CLIENT isn't in FIPS mode (libcrypto ${S2N_LIBCRYPTO:-unknown}); ./setup.sh --fips builds s2n-tls/build-fips, or use --no-s2n"
  fi
  # AWS-LC's entropy configuration (setup.sh --awslc-no-jitter): the stock
  # build seeds its RNG from CPU jitter (~17 ms per process), the other from
  # the OS only. Read from each binary's symbols; differing builds are listed.
  # A FIPS build always uses CPU jitter (AWS-LC refuses to build without it),
  # and may be a shared library, which the symbols wouldn't show.
  if [ "$FIPS" = 1 ]; then
    AWSLC_ENTROPY="CPU jitter (stock; required by the FIPS build)"
  else
    _e_c=$(awslc_entropy "$S2N_CLIENT"); _e_s=$(awslc_entropy "$S2N_SERVER")
    _e_b=$( [ -n "$BSSL" ] && [ -x "$BSSL" ] && awslc_entropy "$BSSL" || echo "$_e_c")
    if [ "$_e_c" = "$_e_s" ] && [ "$_e_c" = "$_e_b" ]; then AWSLC_ENTROPY=$_e_c
    else AWSLC_ENTROPY="s2nc $_e_c; s2nd $_e_s; bssl $_e_b"; fi
  fi
  # --fips: bssl (the primitive benchmarks) must be AWS-LC FIPS too
  if [ "$FIPS" = 1 ] && [ -n "$BSSL" ] && [ -x "$BSSL" ] && [ "$("$BSSL" isfips 2>/dev/null)" != 1 ]; then
    die "--fips: $BSSL isn't AWS-LC FIPS (bssl isfips); ./setup.sh --fips builds aws-lc/aws-lc-fips-install"
  fi
}
s2n_cleanup() { [ -z "$S2N_FIFO" ] || rm -f "$S2N_FIFO"; }

s2n_label() { echo "s2n-tls ($S2N_VERSION)"; }
s2n_info() { info "AWS-LC entropy: $AWSLC_ENTROPY"; }
s2n_env() {
  echo "s2n-tls client: $S2N_CLIENT"
  echo "s2n-tls server: $S2N_SERVER"
  echo "s2n-tls version: $S2N_VERSION"
  echo "aws-lc entropy: $AWSLC_ENTROPY"
  echo "aws-lc bench: ${BSSL:-not found}"
}
s2n_fips_env() {
  echo "fips aws-lc: ${S2N_LIBCRYPTO:-libcrypto unknown}; s2nc and s2nd in FIPS mode; $(libcrypto_linkage "$S2N_CLIENT") libcrypto"
}
s2n_fips_desc() { echo "s2n-tls on $S2N_LIBCRYPTO"; }

s2n_speed() { # kem|mldsa
  if [ "$1" = kem ]; then _af=$BSSL_SPEED_KEM; else _af=$BSSL_SPEED_MLDSA; fi
  hdr "Primitives ($_what): AWS-LC bssl speed (s2n-tls's libcrypto, ${SPEED_SECONDS}s per test)"
  if [ -z "$BSSL" ] || [ ! -x "$BSSL" ]; then
    warn "AWS-LC bssl not found (set BSSL); skipping"
    return 0
  fi
  info "bssl speed filters: $_af"
  "$BSSL" speed -timeout "$SPEED_SECONDS" -threads 1 -filter "$_af" 2>&1 | tee "$_pd/awslc-$1.txt" | sed 's/^/    /'
}

s2n_cli_skip() { # GROUP  (uses CERTK)
  if [ "$(s2n_srv_policy "$1")" = UNSUPPORTED ]; then
    echo "s2n-tls doesn't implement $1"
  elif [ "$(s2n_cli_policy "$1" "$CERTK")" = SKIP ]; then
    if [ "$CERTK" = ec ]; then echo "can't pin group on s2n-tls client"
    else echo "no built-in s2n-tls policy pins this group with $(certk_desc) signatures"; fi
  fi
  return 0
}
s2n_srv_skip() { # GROUP
  [ "$(s2n_srv_policy "$1")" = UNSUPPORTED ] && echo "s2n-tls doesn't implement $1"
  return 0
}
# ML-DSA mode: how to bring s2n-tls pairs in when it lacks MLDSA_GROUP, and
# why its client sits out a profile
s2n_mldsa_hint() {
  if [ "$FIPS" = 1 ]; then echo "set MLDSA_GROUP=X25519MLKEM768, or use --pure-pq, to include it"
  else echo "set MLDSA_GROUP=X25519MLKEM768 or X25519, or use --pure-pq, to include it"; fi
}
s2n_mldsa_cli_skip() { # GROUP  (uses CERTK)
  [ "$(s2n_cli_policy "$1" "$CERTK")" = SKIP ] &&
    echo "no built-in s2n-tls policy pins $1 with $(certk_desc) signatures (X25519 and X25519MLKEM768 accept every ML-DSA level, MLKEM1024 only ML-DSA-87; --pure-pq falls back)"
  return 0
}

s2n_server() { # GROUP PORT LOG KEYS
  _sv_log=$3; _sv_keys=$4; _sv_port=$2
  # no --parallelize: forking a handler per connection cost ~0.7 ms per
  # handshake. Without it a failed handshake ends s2nd, and ensure_server
  # restarts it (as for the wolfSSL example server).
  set -- -w -s -c "$(s2n_srv_policy "$1")" --cert "$SRV_CERT" --key "$SRV_KEY"
  [ -n "$SRV_CA" ] && set -- "$@" -m -t "$SRV_CA"
  # --fips: s2nd exits unless its libcrypto is in FIPS mode
  [ "$FIPS" = 1 ] && set -- "$@" --enter-fips-mode
  # long form only: s2nd's usage lists -L, but its getopt string lacks it
  [ -n "$_sv_keys" ] && set -- "$@" --key-log "$_sv_keys"
  SSL_CERT_FILE=$S2N_NOCERTS SSL_CERT_DIR=$S2N_NOCERTS_DIR \
    "$S2N_SERVER" "$@" "$SERVER_ADDR" "$_sv_port" </dev/null >>"$_sv_log" 2>&1 &
}
# s2nd listens before it has finished setting up (checking its built-in DH
# parameters takes ~0.2 s); a client connecting sooner waits in the accept queue
s2n_ready() { sleep 0.5 2>/dev/null || sleep 1; }

s2n_client() { # GROUP PORT [brief]
  s2n_run_client "$(s2n_cli_policy "$1" "$CERTK")" "$2" "$CLI_CA" "$CLI_CERT" "$CLI_KEY"
}
# s2nc prints the server's response only in echo mode (-e), where it also reads
# stdin and quits at EOF. Its stdin is a FIFO it opens read-write itself, so it
# never sees EOF and leaves once the server has answered and closed.
# SSL_CERT_FILE/SSL_CERT_DIR point AWS-LC's default trust store at nothing:
# s2nc and s2nd otherwise parse the system CA bundle on every start, while the
# OpenSSL and wolfSSL clients load only the CA file they are given.
s2n_run_client() { # POLICY PORT CA [CERT KEY]
  _sc_port=$2; _sc_cert=${4:-}; _sc_key=${5:-}
  set -- -c "$1" -f "$3" -n localhost -e --send-file "$S2N_REQ"
  [ -n "$_sc_cert" ] && set -- "$@" -l "$_sc_cert" -k "$_sc_key"
  [ -n "$CLI_KEYS" ] && set -- "$@" --key-log "$CLI_KEYS"
  # shellcheck disable=SC2086
  SSL_CERT_FILE=$S2N_NOCERTS SSL_CERT_DIR=$S2N_NOCERTS_DIR \
    $TO_CMD "$S2N_CLIENT" "$@" "$CONNECT_HOST" "$_sc_port" <>"$S2N_FIFO"
}

s2n_confirm() { # PREFLIGHT_LOG GROUP
  _sf_neg=$(sed -n -e 's/^KEM Group: *\([^ ]*\).*/\1/p' -e 's/^Curve: *//p' "$1" | head -n 1)
  _sf_pol=$(s2n_cli_policy "$2" "$CERTK")
  if [ -n "$_sf_neg" ] && [ "$(vs_norm_group "$_sf_neg")" = "$2" ]; then
    _sf_note="group confirmed by s2nc (policy $_sf_pol)"
  else
    _sf_note="group set by s2n-tls policy $_sf_pol (negotiated ${_sf_neg:-not reported})"
  fi
  if grep -q '^Handshake:.*HELLO_RETRY_REQUEST' "$1"; then _sf_note="$_sf_note after a HelloRetryRequest"; fi
  # policies that send a second key share next to the group under test (POLICY TABLE)
  case $_sf_pol in
    default_pq|default_fips|test_all_fips) _sf_note="$_sf_note; the policy also sends a P-256 key share" ;;
    20260513)                              _sf_note="$_sf_note; the policy also sends a P-384 key share" ;;
  esac
  echo "$_sf_note"
}

# s2nc until its connect is refused: process start plus s2n_init. With stock
# AWS-LC that includes seeding its CPU-jitter entropy source (~17 ms on an
# Apple M-series Mac), which every s2nc handshake pays too
s2n_startup() {
  SSL_CERT_FILE=$S2N_NOCERTS SSL_CERT_DIR=$S2N_NOCERTS_DIR \
    $TO_CMD "$S2N_CLIENT" 127.0.0.1 "$S2N_CLOSED_PORT" >/dev/null 2>&1
}
s2n_startup_note() {
  info "  (s2n: s2nc until a refused connect, so it includes s2n_init and AWS-LC's entropy seeding: $AWSLC_ENTROPY)"
}

s2n_inproc_bin() { printf '%s\n' "$HSLOOP_S2N"; }
s2n_inproc_exec() { # GROUP COMMAND...
  _si_group=$1; shift
  SSL_CERT_FILE=$S2N_NOCERTS SSL_CERT_DIR=$S2N_NOCERTS_DIR \
    "$@" --policy "$(s2n_cli_policy "$_si_group" "$CERTK")"
}

s2n_keylogs() { return 0; }

# ---- versions mode ----
# s2n-tls policy for each setting: the closest built-in ones (s2n-tls POLICY
# TABLE). Differences: its hybrid client also sends a P-256 key share, its
# ML-KEM-only client a P-384 one, and its classical servers also take P-384.
vs_s_cpolicy() { # VERSION GROUPS
  case $2:$1 in
    classical:1.2) echo 20240501 ;;                        # TLS 1.2 only
    classical:1.3) echo CloudFront-TLS-1-3-2025-no-pq ;;   # TLS 1.3 only, X25519 first
    classical:*)   echo 20241106 ;;                        # TLS 1.2-1.3, X25519 first
    hybrid:1.2)    echo 20240501 ;;                        # no hybrid groups on TLS 1.2
    hybrid:1.3)    echo CloudFront-Upstream-TLS-1-3-2025-PQ ;;
    hybrid:*)      echo default_pq ;;                      # TLS 1.2-1.3, ML-DSA signatures
    pq:*)          echo 20260513 ;;                        # TLS 1.3 only, ML-KEM-1024
  esac
}
vs_s_spolicy() { # VERSION GROUPS
  case $2:$1 in
    *:1.2)         echo 20240501 ;;                        # no PQ groups on TLS 1.2
    classical:1.3) echo CloudFront-TLS-1-3-2025-no-pq ;;
    classical:*)   echo 20241106 ;;
    any:1.3)       echo CloudFront-Upstream-TLS-1-3-2025-PQ ;;  # hybrids, ML-DSA signatures
    any:*)         echo test_all ;;                        # every group, ML-DSA signatures
  esac
}

s2n_vs_server() { # PORT LOG KEYS
  _sw_port=$1; _sw_log=$2; _sw_keys=$3
  # --parallelize keeps s2nd up after the refusals this mode expects, so its
  # time-to-refusal samples don't follow a restart (vs_time KEEPS=1)
  set -- -w -s --parallelize -c "$(vs_s_spolicy "$VS_SV" "$VS_SG")" --cert "$VS_SCERT" --key "$VS_SKEY"
  [ -n "$_sw_keys" ] && set -- "$@" --key-log "$_sw_keys"
  SSL_CERT_FILE=$S2N_NOCERTS SSL_CERT_DIR=$S2N_NOCERTS_DIR \
    "$S2N_SERVER" "$@" "$SERVER_ADDR" "$_sw_port" </dev/null >>"$_sw_log" 2>&1 &
}

s2n_vs_client() { # PORT [brief]
  s2n_run_client "$(vs_s_cpolicy "$VS_CV" "$VS_CG")" "$1" "$VS_CA"
}

# s2nc reports the version, group and a HelloRetryRequest itself; its own
# connection report comes before any echoed page (an s2nd page repeats these lines)
s2n_vs_parse() { # LOG
  VS_VER=$(sed -n -e 's/^Actual protocol version: *33$/1.2/p' \
             -e 's/^Actual protocol version: *34$/1.3/p' "$1" | head -n 1)
  VS_RAWGRP=$(sed -n -e 's/^KEM Group: *\([^ ]*\).*/\1/p' -e 's/^Curve: *//p' "$1" | head -n 1)
  if grep -q '^Handshake:.*HELLO_RETRY_REQUEST' "$1"; then VS_HRRSEEN=yes; else VS_HRRSEEN=no; fi
}

S2N_VS_PQNOTE="s2n-tls client policy 20260513 sends a P-384 key share next to ML-KEM-1024 (no built-in ML-KEM-only policy accepts ECDSA certificates)"
s2n_vs_expect() { # SCENARIO SERVER
  case $1 in
    hybrid-hrr)      VS_NOTE="s2n-tls client policy default_pq also sends a P-256 key share, so a server that takes P-256 needs no HRR" ;;
    pq13|pq-down12)  VS_NOTE=$S2N_VS_PQNOTE ;;
    pq-vs-classical) VS_NOTE=$S2N_VS_PQNOTE
                     if [ "$2" = s2n ]; then
                       VS_EXPECT=1.3/classical
                       VS_NOTE="$S2N_VS_PQNOTE, and every built-in classical s2n-tls server policy accepts P-384"
                     fi ;;
  esac
}
