# shellcheck shell=sh
# pqcbench.sh library: OpenSSL (s_server / s_client, openssl speed, hsloop-openssl).
# Sourced by pqcbench.sh; see LIBRARY INTERFACE there for what each function does.

LIBNAME_openssl=OpenSSL
LIBREQ_openssl=1

openssl_defaults() {
  : "${OPENSSL:=}"
  # Default: OpenSSL built by setup.sh (next to pqcbench.sh, or in the current
  # directory), else openssl on PATH.
  if [ -z "$OPENSSL" ]; then
    for _cand in "$PQCB_DIR/openssl/openssl-install/bin/openssl" ./openssl/openssl-install/bin/openssl; do
      if [ -x "$_cand" ]; then OPENSSL=$_cand; break; fi
    done
    : "${OPENSSL:=openssl}"
  fi
  # --fips: the OpenSSL FIPS provider built by setup.sh
  : "${OPENSSL_FIPS_DIR:=}"
  if [ -z "$OPENSSL_FIPS_DIR" ]; then
    for _cand in "$PQCB_DIR/openssl-fips/openssl-fips-install" ./openssl-fips/openssl-fips-install; do
      if [ -d "$_cand" ]; then OPENSSL_FIPS_DIR=$_cand; break; fi
    done
  fi
  # hsloop-openssl serves --fips too: OpenSSL's FIPS mode comes from OPENSSL_CONF
  : "${HSLOOP_OPENSSL:=${HSLOOP_DIR:+$HSLOOP_DIR/hsloop-openssl}}"

  # `openssl speed` algorithm lists (unknown names are skipped)
  OSSL_SPEED_KEM="ML-KEM-512 ML-KEM-768 ML-KEM-1024
X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024
ecdhx25519 ecdhp256 ecdhp384
rsa2048 rsa3072"
  OSSL_SPEED_MLDSA="ML-DSA-44 ML-DSA-65 ML-DSA-87
ecdsap256 ecdsap384 ed25519
rsa2048 rsa3072"
  # --fips: no X25519
  if [ "$FIPS" = 1 ]; then
    OSSL_SPEED_KEM=$(printf '%s\n' "$OSSL_SPEED_KEM" | sed 's/ecdhx25519 //')
  fi
}

openssl_detect() {
  have "$OPENSSL" || [ -x "$OPENSSL" ] || die "openssl not found ($OPENSSL)"
  case $OPENSSL in */*) OPENSSL=$(abspath "$OPENSSL") ;; esac
  [ -n "$HSLOOP_OPENSSL" ] && HSLOOP_OPENSSL=$(abspath "$HSLOOP_OPENSSL")
  OSSL_VER=$("$OPENSSL" version)
  _mm=$(printf '%s\n' "$OSSL_VER" | sed -n 's/^OpenSSL \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p')
  if [ -n "$_mm" ]; then
    # shellcheck disable=SC2086
    set -- $_mm
    if [ "$1" -lt 3 ] || { [ "$1" -eq 3 ] && [ "$2" -lt 5 ]; }; then
      warn "$OSSL_VER: ML-KEM and ML-DSA need OpenSSL 3.5+"
    fi
  else
    warn "unrecognised OpenSSL version string: $OSSL_VER"
  fi

  # --fips: OpenSSL loads the FIPS provider through setup.sh's openssl-fips.cnf
  # (fips + base providers, default_properties fips=yes), exported so that
  # every openssl command and hsloop-openssl runs in FIPS mode
  OSSL_FIPS=
  [ "$FIPS" = 1 ] || return 0
  if [ -z "$OPENSSL_FIPS_DIR" ] || [ ! -f "$OPENSSL_FIPS_DIR/ssl/openssl-fips.cnf" ]; then
    die "--fips: OpenSSL FIPS provider not found${OPENSSL_FIPS_DIR:+ in $OPENSSL_FIPS_DIR} (./setup.sh --fips builds it; or set OPENSSL_FIPS_DIR)"
  fi
  OPENSSL_FIPS_DIR=$(cd "$OPENSSL_FIPS_DIR" && pwd)
  OPENSSL_CONF=$OPENSSL_FIPS_DIR/ssl/openssl-fips.cnf
  OPENSSL_MODULES=$OPENSSL_FIPS_DIR/lib/ossl-modules
  export OPENSSL_CONF OPENSSL_MODULES
  OSSL_FIPS=$("$OPENSSL" list -providers 2>/dev/null | awk '/^  [^ ]/ { p = $1 }
    p == "fips" && $1 == "name:" { sub(/^ *name: */, ""); n = $0 }
    p == "fips" && $1 == "version:" { v = $2 } p == "fips" && $1 == "status:" { s = $2 }
    END { if (s == "active") print n " " v }')
  [ -n "$OSSL_FIPS" ] ||
    die "--fips: $OPENSSL doesn't load the FIPS provider (run OPENSSL_CONF=$OPENSSL_CONF OPENSSL_MODULES=$OPENSSL_MODULES $OPENSSL list -providers to see why)"
  # approved algorithms only: X25519 (outside the FIPS provider) must be refused
  if "$OPENSSL" genpkey -algorithm X25519 >/dev/null 2>&1; then
    die "--fips: OpenSSL still offers X25519 with $OPENSSL_CONF, so it isn't restricted to the FIPS provider"
  fi
}

openssl_prepare() {
  if [ "$FIPS" = 1 ]; then
    mkdir -p "$OUTDIR/tools" && cp "$OPENSSL_CONF" "$OUTDIR/tools/openssl-fips.cnf"
  fi
}

openssl_label() { echo OpenSSL; }
openssl_env() { echo "openssl: $OSSL_VER ($(command -v "$OPENSSL" || echo "$OPENSSL"))"; }
openssl_fips_env() {
  echo "fips openssl: $OSSL_FIPS ($OPENSSL_MODULES), default_properties fips=yes (tools/openssl-fips.cnf)"
}
openssl_fips_desc() { echo "$OSSL_FIPS (fips=yes)"; }

openssl_speed() { # kem|mldsa
  if [ "$1" = kem ]; then _algs=$OSSL_SPEED_KEM; else _algs=$OSSL_SPEED_MLDSA; fi
  hdr "Primitives ($_what): openssl speed (${SPEED_SECONDS}s per algorithm)"
  for _alg in $_algs; do
    _f=$_pd/openssl-$_alg.txt
    if "$OPENSSL" speed -seconds "$SPEED_SECONDS" "$_alg" >"$_f" 2>&1; then
      printf '%s%s%s\n' "$C_B" "$_alg" "$C_0"
      # keep the summary table, drop progress + build banner lines
      grep -vE '^(Doing|\+|version:|built on:|options:|compiler:|CPUINFO:|OpenSSL )' "$_f" \
        | sed '/^[[:space:]]*$/d; s/^/    /'
    else
      warn "openssl speed: '$_alg' not supported by this build (see $_f)"
    fi
  done
}

# -groups pins both sides to GROUP, so OpenSSL can use every group
openssl_cli_skip() { :; }
openssl_srv_skip() { :; }

openssl_server() { # GROUP PORT LOG KEYS
  _os_log=$3; _os_keys=$4
  set -- s_server -4 -accept "$2" -tls1_3 -groups "$1" \
    -cert "$SRV_CERT" -key "$SRV_KEY" -www -quiet
  [ -n "$SRV_CA" ] && set -- "$@" -CAfile "$SRV_CA" -Verify 1 -verify_return_error
  [ -n "$_os_keys" ] && set -- "$@" -keylogfile "$_os_keys"
  "$OPENSSL" "$@" </dev/null >>"$_os_log" 2>&1 &
}

openssl_client() { # GROUP PORT [brief]
  if [ -n "${3:-}" ]; then _oc_mode=-brief; else _oc_mode=-quiet; fi
  set -- s_client -connect "$CONNECT_HOST:$2" -tls1_3 -groups "$1" \
    -CAfile "$CLI_CA" -servername localhost -verify_return_error "$_oc_mode" -ign_eof
  [ -n "$CLI_CERT" ] && set -- "$@" -cert "$CLI_CERT" -key "$CLI_KEY"
  [ -n "$CLI_KEYS" ] && set -- "$@" -keylogfile "$CLI_KEYS"
  # shellcheck disable=SC2086
  printf 'GET / HTTP/1.0\r\n\r\n' | $TO_CMD "$OPENSSL" "$@"
}

# preflight: OpenSSL 3.5 prints "Negotiated TLS1.3 group" for KEM groups and
# "Peer Temp Key" for (EC)DH ones; older builds "Server Temp Key". Either way
# -groups pins the client to the group.
openssl_confirm() { # PREFLIGHT_LOG GROUP
  _oc_neg=$(sed -n 's/^Negotiated TLS1\.3 group: *//p' "$1" | head -n 1)
  [ -n "$_oc_neg" ] || _oc_neg=$(sed -n -e 's/^Peer Temp Key: *//p' -e 's/^Server Temp Key: *//p' "$1" | head -n 1)
  case $2 in
    P-256) _oc_alias='P-256|prime256v1|secp256r1' ;;
    P-384) _oc_alias='P-384|secp384r1' ;;
    *)     _oc_alias=$2 ;;
  esac
  if [ -n "$_oc_neg" ] && printf '%s\n' "$_oc_neg" | grep -qiE "^($_oc_alias)([ ,]|$)|, ($_oc_alias),"; then
    echo "group confirmed by s_client"
  else
    echo "group pinned by s_client -groups ($(printf '%s' "${_oc_neg:-not reported}" | tr ',' ';'))"
  fi
}
# s_server -groups accepts only GROUP, whatever the client offers
openssl_srv_pin_note() { echo "group pinned by s_server"; }

openssl_startup() { $TO_CMD "$OPENSSL" version >/dev/null 2>&1; }

openssl_inproc_bin() { printf '%s\n' "$HSLOOP_OPENSSL"; }

openssl_keylogs() { return 0; }

# ---- versions mode ----
vs_o_ver() { case $1 in 1.2) echo "-tls1_2" ;; 1.3) echo "-tls1_3" ;;
                        any) echo "-min_protocol TLSv1.2 -max_protocol TLSv1.3" ;; esac; }
vs_o_cgroups() { case $1 in classical) echo "-groups X25519:P-256" ;;
                            hybrid) echo "-groups X25519MLKEM768:X25519:P-256" ;;
                            pq) echo "-groups MLKEM1024" ;; esac; }
# "any" = every group these tests use, in one preference tuple so the server
# takes whichever key share the client sent. (OpenSSL 3.5's *default* server
# list has no pure ML-KEM group, so an ML-KEM-only client can't reach it.)
VS_O_ANY="X25519MLKEM768:MLKEM1024:SecP256r1MLKEM768:X25519:P-256:P-384"
vs_o_sgroups() { case $1 in classical) echo "-groups X25519:P-256" ;; *) echo "-groups $VS_O_ANY" ;; esac; }

openssl_vs_server() { # PORT LOG KEYS
  _ov_log=$2; _ov_keys=$3
  # shellcheck disable=SC2046
  set -- s_server -4 -accept "$1" $(vs_o_ver "$VS_SV") $(vs_o_sgroups "$VS_SG") \
    -cert "$VS_SCERT" -key "$VS_SKEY" -www -quiet
  [ -n "$_ov_keys" ] && set -- "$@" -keylogfile "$_ov_keys"
  "$OPENSSL" "$@" </dev/null >>"$_ov_log" 2>&1 &
}

openssl_vs_client() { # PORT [brief]
  if [ -n "${2:-}" ]; then _ovc_mode=-brief; else _ovc_mode=-quiet; fi
  # shellcheck disable=SC2046
  set -- s_client -connect "$CONNECT_HOST:$1" $(vs_o_ver "$VS_CV") $(vs_o_cgroups "$VS_CG") \
    -CAfile "$VS_CA" -servername localhost -verify_return_error "$_ovc_mode" -ign_eof
  [ -n "$CLI_KEYS" ] && set -- "$@" -keylogfile "$CLI_KEYS"
  # shellcheck disable=SC2086
  printf 'GET / HTTP/1.0\r\n\r\n' | $TO_CMD "$OPENSSL" "$@"
}
