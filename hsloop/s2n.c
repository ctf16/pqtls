/* hsloop adapter: s2n-tls (on AWS-LC). s2n-tls has no group setting: the group
 * comes from a built-in security policy (--policy), chosen by pqcbench.sh from
 * its s2n-tls POLICY TABLE, as for s2nc. Self-service blinding keeps a failed
 * handshake from sleeping 10-30 s. */
#include "hsloop.h"

#include <s2n.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *hs_lib_name = "s2n";
static struct s2n_config *config;
static struct s2n_cert_chain_and_key *chain_and_key;
static struct s2n_connection *conn;

static void s2n_err(const char *what, char *err, size_t errlen)
{
    snprintf(err, errlen, "%s: %s (%s)", what, s2n_strerror(s2n_errno, "EN"),
             s2n_strerror_debug(s2n_errno, "EN"));
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    long n;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0 &&
        (buf = malloc((size_t)n + 1)) && fread(buf, 1, (size_t)n, f) == (size_t)n) {
        buf[n] = 0;
    } else {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    return buf;
}

int hs_lib_setup(const hs_opts *o, char *err, size_t errlen)
{
    if (!o->policy) {
        snprintf(err, errlen, "--policy is required for s2n-tls");
        return -1;
    }
    /* s2n_init seeds AWS-LC's random number generator (CPU jitter entropy in the
     * stock build), so library start-up cost falls into init */
    if (s2n_init() != S2N_SUCCESS || !(config = s2n_config_new())) {
        s2n_err("s2n_init", err, errlen);
        return -1;
    }
    if (s2n_config_set_cipher_preferences(config, o->policy) != S2N_SUCCESS) {
        s2n_err("security policy", err, errlen);
        return -1;
    }
    if (s2n_config_wipe_trust_store(config) != S2N_SUCCESS ||
        s2n_config_set_verification_ca_location(config, o->ca, NULL) != S2N_SUCCESS) {
        s2n_err("cannot load CA file", err, errlen);
        return -1;
    }
    if (s2n_config_set_session_tickets_onoff(config, 0) != S2N_SUCCESS) {
        s2n_err("session tickets", err, errlen);
        return -1;
    }
    if (o->cert) {
        char *cert = read_file(o->cert), *key = read_file(o->key);
        int rc = -1;
        if (cert && key && (chain_and_key = s2n_cert_chain_and_key_new()) &&
            s2n_cert_chain_and_key_load_pem(chain_and_key, cert, key) == S2N_SUCCESS &&
            s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key) == S2N_SUCCESS)
            rc = 0;
        free(cert);
        free(key);
        if (rc != 0) {
            s2n_err("cannot load client certificate/key", err, errlen);
            return -1;
        }
    }
    return 0;
}

int hs_lib_handshake(int fd, const hs_opts *o, char *err, size_t errlen)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    if (!(conn = s2n_connection_new(S2N_CLIENT)) ||
        s2n_connection_set_config(conn, config) != S2N_SUCCESS ||
        s2n_connection_set_fd(conn, fd) != S2N_SUCCESS ||
        s2n_set_server_name(conn, o->sni) != S2N_SUCCESS ||
        s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING) != S2N_SUCCESS ||
        /* answer a CertificateRequest with the configured certificate, as s2nc does */
        s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL) != S2N_SUCCESS) {
        s2n_err("connection setup", err, errlen);
        return -1;
    }
    while (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            s2n_err("handshake", err, errlen);
            return -1;
        }
    }
    return 0;
}

void hs_lib_info(char *group, size_t glen, char *version, size_t vlen)
{
    const char *g = NULL;
    int v = conn ? s2n_connection_get_actual_protocol_version(conn) : 0;
    if (conn && s2n_connection_get_key_exchange_group(conn, &g) != S2N_SUCCESS) g = NULL;
    snprintf(group, glen, "%s", g ? g : "");
    snprintf(version, vlen, "%s", v == S2N_TLS13 ? "TLSv1.3" : v == S2N_TLS12 ? "TLSv1.2" : "");
}

int hs_lib_write(const void *buf, size_t len, char *err, size_t errlen)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    size_t done = 0;
    while (done < len) {
        ssize_t n = s2n_send(conn, (const char *)buf + done, (ssize_t)(len - done), &blocked);
        if (n < 0) {
            if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) continue;
            s2n_err("s2n_send", err, errlen);
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

long hs_lib_read_all(char *head, size_t headlen, char *err, size_t errlen)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    char buf[16384];
    long total = 0;
    head[0] = 0;
    for (;;) {
        ssize_t n = s2n_recv(conn, buf, sizeof(buf), &blocked);
        if (n > 0) {
            if ((size_t)total < headlen - 1) {
                size_t k = headlen - 1 - (size_t)total;
                if (k > (size_t)n) k = (size_t)n;
                memcpy(head + total, buf, k);
                head[total + k] = 0;
            }
            total += n;
            continue;
        }
        if (n == 0) return total;   /* close_notify or TCP close */
        if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) continue;
        if (total > 0 && s2n_error_get_type(s2n_errno) == S2N_ERR_T_CLOSED) return total;
        s2n_err("s2n_recv", err, errlen);
        return -1;
    }
}

void hs_lib_close(void)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    if (!conn) return;
    /* best effort: the server has usually closed already */
    s2n_shutdown_send(conn, &blocked);
    s2n_connection_free(conn);
    conn = NULL;
}

void hs_lib_teardown(void)
{
    s2n_config_free(config);
    config = NULL;
    if (chain_and_key) s2n_cert_chain_and_key_free(chain_and_key);
    chain_and_key = NULL;
    s2n_cleanup_final();
}
