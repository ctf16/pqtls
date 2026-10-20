# shellcheck shell=sh
# pqcbench.sh library: rustls 0.23 with one or more crypto providers
# (--rustls-provider, default aws-lc-rs): pqc-rustls client/server/speed and
# hsloop-rustls-<provider>, built by setup.sh in rustls-tools/. Optional: left
# out when not built, or with --no-rustls. Sourced by pqcbench.sh; see LIBRARY
# INTERFACE there.
#
# One provider runs as the library `rustls`. Several run side by side, each as
# its own library rustls_<provider> (dashes as underscores, e.g.
# rustls_aws_lc_rs), so every provider meets every other one, and the other
# libraries, in the client x server matrix. rustls_instances defines each
# instance's hooks (<id>_<hook>), which run the rl_<hook> functions below with
# that instance's provider (rl_use).
#
# What a provider can do comes from `pqc-rustls caps` (groups, TLS versions,
# signature schemes it verifies), so its pairs are skipped with a reason where
# it lacks a group or ML-DSA, rather than failing.

LIBNAME_rustls=rustls
LIBREQ_rustls=0
RUSTLS_PROVIDERS_ALL="aws-lc-rs ring graviola graviola-pq rustcrypto rustcrypto-pq libcrux-pq wolfcrypt"
# the hooks every instance has
RUSTLS_HOOKS="detect prepare label info env fips_env fips_desc speed cli_skip srv_skip server
client confirm startup startup_note inproc_bin keylogs mldsa_hint vs_server vs_client vs_parse vs_skip"

rustls_defaults() {
  : "${RUSTLS_PROVIDER:=aws-lc-rs}"
  # one provider's programs (binaries are chosen in rl_detect, after --rustls-provider)
  : "${RUSTLS_BIN:=}"
  : "${HSLOOP_RUSTLS:=}"
}

rustls_option() { # ARGS...  -> OPT_SHIFT, or 1 if not a rustls option
  case $1 in
    --rustls-provider)   [ $# -ge 2 ] || die "$1 needs a value"; RUSTLS_PROVIDER=$2; OPT_SHIFT=2 ;;
    --rustls-provider=*) RUSTLS_PROVIDER=${1#*=}; OPT_SHIFT=1 ;;
    *) return 1 ;;
  esac
}

# the libraries rustls runs as (LIB_INSTANCES), from --rustls-provider: one
# provider, a list (commas or spaces), or all. --fips runs aws-lc-rs's FIPS
# build. RL_ALL=1: "all" (providers that aren't built are left out quietly).
RL_ALL=0
rustls_instances() {
  _rn_w=$(printf '%s\n' "$RUSTLS_PROVIDER" | tr ',' ' ')
  if [ "$_rn_w" = all ]; then _rn_w=$RUSTLS_PROVIDERS_ALL; RL_ALL=1; fi
  _rn_l=
  for _rn_p in $_rn_w; do
    case " $RUSTLS_PROVIDERS_ALL " in
      *" $_rn_p "*) ;;
      *) die "--rustls-provider $_rn_p: unknown (one of: $RUSTLS_PROVIDERS_ALL; a list; or all)" ;;
    esac
    case " $_rn_l " in *" $_rn_p "*) ;; *) _rn_l="$_rn_l $_rn_p" ;; esac
  done
  # shellcheck disable=SC2086
  set -- $_rn_l
  [ $# -gt 0 ] || die "--rustls-provider needs a provider"
  [ $# -eq 1 ] || [ -z "$RUSTLS_BIN$HSLOOP_RUSTLS" ] ||
    die "RUSTLS_BIN and HSLOOP_RUSTLS name one provider's programs: use them with a single --rustls-provider"
  LIB_INSTANCES=
  for _rn_p in "$@"; do
    _rn_b=$_rn_p; [ "$FIPS" = 1 ] && [ "$_rn_p" = aws-lc-rs ] && _rn_b=aws-lc-rs-fips
    if [ $# -eq 1 ]; then
      _rn_i=rustls
    else
      _rn_i=rustls_$(printf '%s' "$_rn_b" | tr - _)
      eval "LIBNAME_$_rn_i=\"rustls (\$_rn_b)\"; LIBREQ_$_rn_i=0"
    fi
    # webpki matches the server name against the subjectAltName only
    eval "LIBSANONLY_$_rn_i=1; RL_PROV_$_rn_i=\$_rn_p; RL_BUILD_$_rn_i=\$_rn_b"
    eval "RL_BIN_$_rn_i=; RL_HSLOOP_$_rn_i=; RL_CAPS_$_rn_i=; RL_VERS_$_rn_i="
    for _rn_h in $RUSTLS_HOOKS; do
      eval "${_rn_i}_$_rn_h() { rl_use $_rn_i; rl_$_rn_h \"\$@\"; }"
    done
    LIB_INSTANCES="${LIB_INSTANCES:+$LIB_INSTANCES }$_rn_i"
  done
}

# instance ID's provider, programs and capabilities become the current ones
RL_ID=; RL_PROV=; RUSTLS_BUILD=; RL_BIN=; RL_HSLOOP=; RUSTLS_CAPS=; RUSTLS_VERSIONS=
rl_use() { # ID
  RL_ID=$1
  eval "RL_PROV=\$RL_PROV_$1; RUSTLS_BUILD=\$RL_BUILD_$1; RL_BIN=\$RL_BIN_$1; RL_HSLOOP=\$RL_HSLOOP_$1"
  eval "RUSTLS_CAPS=\$RL_CAPS_$1; RUSTLS_VERSIONS=\$RL_VERS_$1"
}
rl_note() { # TEXT WARN(0|1): why this instance is left out
  eval "LIBNOTE_$RL_ID=\$1; LIBNOTE_WARN_$RL_ID=\$2"
}

rl_detect() {
  # warn when it's missing if it was asked for by name (not "all", not just the default)
  _rd_w=1
  if [ "$RL_ALL" = 1 ] || { [ "$RL_PROV" = aws-lc-rs ] && [ -z "$RUSTLS_BIN" ]; }; then _rd_w=0; fi
  if [ "$FIPS" = 1 ] && [ "$RUSTLS_BUILD" != aws-lc-rs-fips ]; then
    rl_note "--fips: rustls's $RL_PROV provider has no FIPS mode (only aws-lc-rs); leaving it out" \
      "$([ "$RL_ALL" = 1 ] && echo 0 || echo 1)"
    return 1
  fi
  _rd_b=$RUSTLS_BIN
  if [ -z "$_rd_b" ]; then
    for _cand in "$PQCB_DIR/rustls-tools/bin" ./rustls-tools/bin; do
      if [ -x "$_cand/pqc-rustls-$RUSTLS_BUILD" ]; then _rd_b=$_cand/pqc-rustls-$RUSTLS_BUILD; break; fi
    done
  fi
  _rd_h=${HSLOOP_RUSTLS:-${HSLOOP_DIR:+$HSLOOP_DIR/hsloop-rustls-$RUSTLS_BUILD}}
  [ -n "$_rd_h" ] && _rd_h=$(abspath "$_rd_h")
  if [ -z "$_rd_b" ] || [ ! -x "$_rd_b" ]; then
    rl_note "rustls ($RUSTLS_BUILD) not found${_rd_b:+ ($_rd_b)} (./setup.sh rustls builds it); leaving it out" "$_rd_w"
    return 1
  fi
  _rd_b=$(abspath "$_rd_b")
  _rd_c=$("$_rd_b" caps) || die "rustls: $_rd_b caps failed"
  _rd_v=; [ -f "$_rd_b.versions" ] && _rd_v=$(cat "$_rd_b.versions")
  eval "RL_BIN_$RL_ID=\$_rd_b; RL_HSLOOP_$RL_ID=\$_rd_h; RL_CAPS_$RL_ID=\$_rd_c; RL_VERS_$RL_ID=\$_rd_v"
  rl_use "$RL_ID"
  if [ "$FIPS" = 1 ] && ! rl_has "fips yes"; then
    die "--fips: $RL_BIN isn't a FIPS provider (./setup.sh --fips rustls builds aws-lc-rs-fips)"
  fi
  return 0
}
rl_has() { printf '%s\n' "$RUSTLS_CAPS" | grep -qxF "$1"; }

# shared by every instance: the startup baseline runs the client until a
# refused connect, with a CA file to load (as every real run does)
RUSTLS_CLOSED_PORT=; RUSTLS_STARTUP_CA=
rl_prepare() {
  [ -n "$RUSTLS_STARTUP_CA" ] && return 0
  _rp_d=$OUTDIR/tools/rustls; mkdir -p "$_rp_d" || die "cannot create $_rp_d"
  RUSTLS_STARTUP_CA=$_rp_d/startup-ca.pem
  printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = startup' > "$_rp_d/req.cnf"
  "$OPENSSL" req -config "$_rp_d/req.cnf" -x509 -newkey EC -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$_rp_d/startup-ca.key" -out "$RUSTLS_STARTUP_CA" -days 2 >/dev/null 2>&1 ||
    die "rustls: creating the startup-baseline CA failed"
  RUSTLS_CLOSED_PORT=$((BASE_PORT - 1)); _rcp=0
  while [ "$PORT_TOOL" != none ] && [ $_rcp -lt 20 ] && port_listening "$RUSTLS_CLOSED_PORT"; do
    RUSTLS_CLOSED_PORT=$((RUSTLS_CLOSED_PORT - 1)); _rcp=$((_rcp + 1))
  done
}

rl_label() { echo "rustls ($RUSTLS_BUILD${RUSTLS_VERSIONS:+; $RUSTLS_VERSIONS})"; }
rl_info() {
  _ri_g=$(printf '%s\n' "$RUSTLS_CAPS" | sed -n 's/^group //p' | tr '\n' ' ')
  info "rustls provider $RUSTLS_BUILD: groups ${_ri_g% }; ML-DSA: $(rl_mldsa_levels)"
  case $RUSTLS_BUILD in aws-lc-rs*) info "rustls ($RUSTLS_BUILD) AWS-LC entropy: $(rl_entropy)" ;; esac
}
rl_mldsa_levels() {
  _rml=$(printf '%s\n' "$RUSTLS_CAPS" | sed -n 's/^verify ML-DSA-//p' | tr '\n' ' ')
  echo "${_rml:-none}"
}
# AWS-LC inside aws-lc-rs: CPU Jitter Entropy (jent_*) or OS only. The FIPS
# module on macOS is the shared library setup.sh put next to the binary.
rl_entropy() {
  if ! have nm; then echo "unknown (no nm)"; return 0; fi
  set -- "$RL_BIN"
  if [ "$RUSTLS_BUILD" = aws-lc-rs-fips ]; then
    for _re_l in "${RL_BIN%/*}"/libaws_lc_fips_*_crypto.dylib; do [ -f "$_re_l" ] && set -- "$@" "$_re_l"; done
  fi
  nm "$@" 2>/dev/null | awk -v kind="${RUSTLS_BUILD#aws-lc-rs}" '{ n = 1 } /jent_/ { j = 1 }
    END { print (!n ? "unknown (no symbols)" : j ? (kind == "-fips" ? "CPU jitter (FIPS module)" : "CPU jitter (stock)") : "OS only (built without CPU jitter)") }'
}
# "<id> setting: value" (one provider: "rustls provider: ring", as before)
rl_env() {
  echo "$RL_ID client/server: $RL_BIN"
  echo "$RL_ID provider: $RUSTLS_BUILD"
  echo "$RL_ID versions: ${RUSTLS_VERSIONS:-unknown}"
  case $RUSTLS_BUILD in aws-lc-rs*) echo "$RL_ID aws-lc entropy: $(rl_entropy)" ;; esac
}
rl_fips_env() { echo "fips $RL_ID: aws-lc-rs FIPS provider (${RUSTLS_VERSIONS:-versions unknown})"; }
rl_fips_desc() { echo "rustls on aws-lc-rs FIPS"; }

# primitives through the provider's rustls interfaces (pqc-rustls speed): key
# exchange for every group it implements; signatures with keys made here
# (once, for every instance). Output: primitives/<id>-kem.txt, <id>-mldsa.txt
rl_speed() { # kem|mldsa
  hdr "Primitives ($_what): rustls $RUSTLS_BUILD provider (pqc-rustls speed, ${SPEED_SECONDS}s per operation)"
  _rs_out=$_pd/$RL_ID-$1.txt
  if [ "$1" = kem ]; then
    set -- --what kx
  else
    _rs_k=$OUTDIR/tools/rustls/keys; mkdir -p "$_rs_k"
    for _rs_x in "ecdsa-p256:-algorithm EC -pkeyopt ec_paramgen_curve:P-256" \
                 "ecdsa-p384:-algorithm EC -pkeyopt ec_paramgen_curve:P-384" "ed25519:-algorithm ED25519" \
                 "rsa2048:-algorithm RSA -pkeyopt rsa_keygen_bits:2048" "rsa3072:-algorithm RSA -pkeyopt rsa_keygen_bits:3072" \
                 "mldsa44:-algorithm ML-DSA-44" "mldsa65:-algorithm ML-DSA-65" "mldsa87:-algorithm ML-DSA-87"; do
      [ -f "$_rs_k/${_rs_x%%:*}.spki.der" ] && continue
      # shellcheck disable=SC2086
      "$OPENSSL" genpkey ${_rs_x#*:} -out "$_rs_k/${_rs_x%%:*}.key" >/dev/null 2>&1 &&
        "$OPENSSL" pkey -in "$_rs_k/${_rs_x%%:*}.key" -pubout -outform DER -out "$_rs_k/${_rs_x%%:*}.spki.der" 2>/dev/null
    done
    set -- --what sig --keys "$_rs_k"
  fi
  "$RL_BIN" speed --seconds "$SPEED_SECONDS" "$@" 2>&1 | tee "$_rs_out" | sed 's/^/    /'
}

# a group it lacks, or the ML-DSA levels of the chain in use (CERTK)
rl_skip() { # GROUP
  if ! rl_has "group $1"; then
    echo "rustls ($RUSTLS_BUILD) doesn't implement $1"; return 0
  fi
  case $CERTK in
    mldsa*)
      _rk=${CERTK#mldsa}
      for _rk_l in ${_rk%-*} ${_rk#*-}; do
        rl_has "verify ML-DSA-$_rk_l" || { echo "rustls ($RUSTLS_BUILD) has no ML-DSA-$_rk_l"; return 0; }
      done ;;
  esac
  return 0
}
rl_cli_skip() { rl_skip "$1"; }
rl_srv_skip() { rl_skip "$1"; }

rl_server() { # GROUP PORT LOG KEYS
  _rv_log=$3; _rv_keys=$4
  set -- server --port "$2" --cert "$SRV_CERT" --key "$SRV_KEY" --groups "$1" --tls 1.3
  [ -n "$SRV_CA" ] && set -- "$@" --ca "$SRV_CA"
  [ -n "$_rv_keys" ] && set -- "$@" --keylog "$_rv_keys"
  [ "$SERVER_ADDR" = 127.0.0.1 ] || set -- "$@" --bind "$SERVER_ADDR"
  "$RL_BIN" "$@" </dev/null >>"$_rv_log" 2>&1 &
}

# the client offers only GROUP, so it sends that key share and nothing else
rl_client() { # GROUP PORT [brief]
  set -- client --host "$CONNECT_HOST" --port "$2" --ca "$CLI_CA" --sni localhost --groups "$1" --tls 1.3 ${3:+--brief}
  [ -n "$CLI_CERT" ] && set -- "$@" --cert "$CLI_CERT" --key "$CLI_KEY"
  # shellcheck disable=SC2086
  SSLKEYLOGFILE=$(cli_keylog_val) $TO_CMD "$RL_BIN" "$@"
}

rl_confirm() { # PREFLIGHT_LOG GROUP
  _rc_neg=$(sed -n 's/^Negotiated group: *//p' "$1" | head -n 1)
  if [ "$_rc_neg" = "$2" ]; then _rc_note="group confirmed by the rustls client (offers only $2)"
  else _rc_note="group set by the rustls client (negotiated ${_rc_neg:-not reported})"; fi
  grep -q '^Handshake: HELLO_RETRY_REQUEST' "$1" && _rc_note="$_rc_note after a HelloRetryRequest"
  echo "$_rc_note"
}

# the client until its connect is refused: process start, provider set-up,
# client configuration (CA file, verifier)
rl_startup() {
  $TO_CMD "$RL_BIN" client --port "$RUSTLS_CLOSED_PORT" --ca "$RUSTLS_STARTUP_CA" >/dev/null 2>&1
}
RL_STARTUP_NOTED=0
rl_startup_note() {
  [ "$RL_STARTUP_NOTED" = 1 ] && return 0
  RL_STARTUP_NOTED=1
  info "  (rustls: pqc-rustls client until a refused connect, so it includes the provider's set-up and the client configuration)"
}

rl_inproc_bin() { printf '%s\n' "$RL_HSLOOP"; }

rl_keylogs() { return 0; }

rl_mldsa_hint() {
  echo "rustls's $RUSTLS_BUILD provider implements: $(printf '%s\n' "$RUSTLS_CAPS" | sed -n 's/^group //p' | tr '\n' ' ' | sed 's/ $//')"
}

# ---- versions mode ----
# the same group sets as the OpenSSL client and server (libs/openssl.sh)
vs_r_cgroups() { case $1 in classical) echo X25519,P-256 ;; hybrid) echo X25519MLKEM768,X25519,P-256 ;; pq) echo MLKEM1024 ;; esac; }
vs_r_sgroups() {
  case $1 in
    classical) echo X25519,P-256 ;;
    *) for _vr_g in X25519MLKEM768 MLKEM1024 SecP256r1MLKEM768 X25519 P-256 P-384; do
         rl_has "group $_vr_g" && printf '%s,' "$_vr_g"
       done | sed 's/,$//' ;;
  esac
}

rl_vs_server() { # PORT LOG KEYS
  _rw_log=$2; _rw_keys=$3
  set -- server --port "$1" --cert "$VS_SCERT" --key "$VS_SKEY" --groups "$(vs_r_sgroups "$VS_SG")" --tls "$VS_SV"
  [ -n "$_rw_keys" ] && set -- "$@" --keylog "$_rw_keys"
  [ "$SERVER_ADDR" = 127.0.0.1 ] || set -- "$@" --bind "$SERVER_ADDR"
  "$RL_BIN" "$@" </dev/null >>"$_rw_log" 2>&1 &
}

rl_vs_client() { # PORT [brief]
  # shellcheck disable=SC2086
  SSLKEYLOGFILE=$(cli_keylog_val) $TO_CMD "$RL_BIN" client --host "$CONNECT_HOST" --port "$1" --ca "$VS_CA" --sni localhost \
    --groups "$(vs_r_cgroups "$VS_CG")" --tls "$VS_CV" ${2:+--brief}
}

# it reports the version, the group and a HelloRetryRequest itself
rl_vs_parse() { # LOG
  VS_VER=$(sed -n 's/^Protocol version: *TLSv//p' "$1" | head -n 1)
  VS_RAWGRP=$(sed -n 's/^Negotiated group: *//p' "$1" | head -n 1)
  if grep -q '^Handshake: HELLO_RETRY_REQUEST' "$1"; then VS_HRRSEEN=yes; else VS_HRRSEEN=no; fi
}

# a scenario this provider can't play as designed: a group, TLS 1.2 or ML-DSA it lacks
rl_vs_skip() { # client|server
  if [ "$1" = client ]; then
    case $VS_CG in hybrid) _rs_g=X25519MLKEM768 ;; pq) _rs_g=MLKEM1024 ;; *) _rs_g=X25519 ;; esac
    _rs_v=$VS_CV
  else
    # its server needs the client's key share (classical clients: X25519)
    case $VS_SG:$VS_CG in any:hybrid) _rs_g=X25519MLKEM768 ;; any:pq) _rs_g=MLKEM1024 ;; *) _rs_g=X25519 ;; esac
    [ "$VS_SV" = 1.2 ] && _rs_g=X25519
    _rs_v=$VS_SV
  fi
  rl_has "group $_rs_g" || { echo "rustls ($RUSTLS_BUILD) $1 doesn't implement $_rs_g"; return 0; }
  [ "$_rs_v" = 1.3 ] || rl_has "version TLSv1.2" || { echo "rustls ($RUSTLS_BUILD) has no TLS 1.2"; return 0; }
  [ "$VS_CERTK" = mldsa ] && ! rl_has "verify ML-DSA-65" && { echo "rustls ($RUSTLS_BUILD) $1 has no ML-DSA-65"; return 0; }
  return 0
}
