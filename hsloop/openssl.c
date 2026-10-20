/* hsloop adapter: OpenSSL 3.x. Mirrors the s_client settings pqcbench.sh uses:
 * TLS 1.3 only, -groups, -CAfile with verification, -servername, -cert/-key. */
#include "hsloop.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

const char *hs_lib_name = "openssl";
static SSL_CTX *ctx;
static SSL *ssl;

static void ossl_err(const char *what, char *err, size_t errlen)
{
    unsigned long e = ERR_get_error();
    char buf[200] = "";
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    snprintf(err, errlen, "%s%s%s", what, buf[0] ? ": " : "", buf);
    ERR_clear_error();
}

int hs_lib_setup(const hs_opts *o, char *err, size_t errlen)
{
    unsigned char seed[32];
    if (!OPENSSL_init_ssl(0, NULL) || !(ctx = SSL_CTX_new(TLS_client_method()))) {
        ossl_err("SSL_CTX_new", err, errlen);
        return -1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    /* full handshakes only */
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (!SSL_CTX_set1_groups_list(ctx, o->group)) {
        ossl_err("unknown group", err, errlen);
        return -1;
    }
    if (!SSL_CTX_load_verify_locations(ctx, o->ca, NULL)) {
        ossl_err("cannot load CA file", err, errlen);
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (o->cert && (SSL_CTX_use_certificate_file(ctx, o->cert, SSL_FILETYPE_PEM) != 1 ||
                    SSL_CTX_use_PrivateKey_file(ctx, o->key, SSL_FILETYPE_PEM) != 1)) {
        ossl_err("cannot load client certificate/key", err, errlen);
        return -1;
    }
    /* first random bytes: library start-up cost belongs to init, not to handshake 1 */
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        ossl_err("RAND_bytes", err, errlen);
        return -1;
    }
    return 0;
}

int hs_lib_handshake(int fd, const hs_opts *o, char *err, size_t errlen)
{
    int rc;
    if (!(ssl = SSL_new(ctx)) || !SSL_set_fd(ssl, fd) || !SSL_set_tlsext_host_name(ssl, o->sni)) {
        ossl_err("SSL_new", err, errlen);
        return -1;
    }
    if ((rc = SSL_connect(ssl)) != 1) {
        char what[64];
        long v = SSL_get_verify_result(ssl);
        if (v != X509_V_OK)
            snprintf(what, sizeof(what), "handshake (verify: %s)", X509_verify_cert_error_string(v));
        else
            snprintf(what, sizeof(what), "handshake (SSL_get_error %d)", SSL_get_error(ssl, rc));
        ossl_err(what, err, errlen);
        return -1;
    }
    return 0;
}

void hs_lib_info(char *group, size_t glen, char *version, size_t vlen)
{
    const char *g = ssl ? SSL_get0_group_name(ssl) : NULL;
    snprintf(group, glen, "%s", g ? g : "");
    snprintf(version, vlen, "%s", ssl ? SSL_get_version(ssl) : "");
}

int hs_lib_write(const void *buf, size_t len, char *err, size_t errlen)
{
    size_t done = 0;
    while (done < len) {
        int n = SSL_write(ssl, (const char *)buf + done, (int)(len - done));
        if (n <= 0) {
            ossl_err("SSL_write", err, errlen);
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

long hs_lib_read_all(char *head, size_t headlen, char *err, size_t errlen)
{
    char buf[16384];
    long total = 0;
    head[0] = 0;
    for (;;) {
        int n = SSL_read(ssl, buf, sizeof(buf));
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
        switch (SSL_get_error(ssl, n)) {
        case SSL_ERROR_ZERO_RETURN:      /* close_notify */
            return total;
        case SSL_ERROR_SYSCALL:          /* TCP close without close_notify */
            ERR_clear_error();
            if (total > 0) return total;
            /* fall through */
        default:
            ossl_err("SSL_read", err, errlen);
            return -1;
        }
    }
}

void hs_lib_close(void)
{
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ssl = NULL;
    ERR_clear_error();
}

void hs_lib_teardown(void)
{
    SSL_CTX_free(ctx);
    ctx = NULL;
}
