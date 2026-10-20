/* hsloop adapter: wolfSSL. Unlike the wolfSSL example client, the group is set
 * through the library API: wolfSSL_CTX_set_groups() limits the supported groups
 * to the one requested and wolfSSL_UseKeyShare() sends its key share, so the
 * client can't fall back to another group. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/random.h>

#include "hsloop.h"

#include <stdio.h>
#include <string.h>

const char *hs_lib_name = "wolfssl";
static WOLFSSL_CTX *ctx;
static WOLFSSL *ssl;
static int group_id;

static const struct { const char *name; int id; } groups[] = {
    {"X25519", WOLFSSL_ECC_X25519},
    {"P-256", WOLFSSL_ECC_SECP256R1},
    {"P-384", WOLFSSL_ECC_SECP384R1},
    {"MLKEM512", WOLFSSL_ML_KEM_512},
    {"MLKEM768", WOLFSSL_ML_KEM_768},
    {"MLKEM1024", WOLFSSL_ML_KEM_1024},
    {"X25519MLKEM768", WOLFSSL_X25519MLKEM768},
    {"SecP256r1MLKEM768", WOLFSSL_SECP256R1MLKEM768},
    {"SecP384r1MLKEM1024", WOLFSSL_SECP384R1MLKEM1024},
};

static void wolf_err(const char *what, int code, char *err, size_t errlen)
{
    char buf[WOLFSSL_MAX_ERROR_SZ];
    wolfSSL_ERR_error_string_n((unsigned long)code, buf, sizeof(buf));
    snprintf(err, errlen, "%s: %s (%d)", what, buf, code);
}

int hs_lib_setup(const hs_opts *o, char *err, size_t errlen)
{
    WC_RNG rng;
    unsigned char seed[32];
    size_t i;
    int rc;

    for (i = 0; i < sizeof(groups) / sizeof(groups[0]); i++)
        if (!strcmp(groups[i].name, o->group)) group_id = groups[i].id;
    if (!group_id) {
        snprintf(err, errlen, "unknown group %s", o->group);
        return -1;
    }
    if (wolfSSL_Init() != WOLFSSL_SUCCESS || !(ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method()))) {
        snprintf(err, errlen, "wolfSSL_CTX_new failed");
        return -1;
    }
    if ((rc = wolfSSL_CTX_set_groups(ctx, &group_id, 1)) != WOLFSSL_SUCCESS) {
        wolf_err("wolfSSL_CTX_set_groups (group not in this build?)", rc, err, errlen);
        return -1;
    }
    if ((rc = wolfSSL_CTX_load_verify_locations(ctx, o->ca, NULL)) != WOLFSSL_SUCCESS) {
        wolf_err("cannot load CA file", rc, err, errlen);
        return -1;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    if (o->cert &&
        ((rc = wolfSSL_CTX_use_certificate_file(ctx, o->cert, WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS ||
         (rc = wolfSSL_CTX_use_PrivateKey_file(ctx, o->key, WOLFSSL_FILETYPE_PEM)) != WOLFSSL_SUCCESS)) {
        wolf_err("cannot load client certificate/key", rc, err, errlen);
        return -1;
    }
    /* first random bytes: library start-up cost belongs to init, not to handshake 1 */
    if (wc_InitRng(&rng) != 0 || wc_RNG_GenerateBlock(&rng, seed, sizeof(seed)) != 0) {
        snprintf(err, errlen, "wolfCrypt RNG failed");
        return -1;
    }
    wc_FreeRng(&rng);
    return 0;
}

int hs_lib_handshake(int fd, const hs_opts *o, char *err, size_t errlen)
{
    int rc;
    if (!(ssl = wolfSSL_new(ctx))) {
        snprintf(err, errlen, "wolfSSL_new failed");
        return -1;
    }
    wolfSSL_set_fd(ssl, fd);
#ifdef HAVE_SNI
    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, o->sni, (unsigned short)strlen(o->sni));
#else
    (void)o;
#endif
    if ((rc = wolfSSL_UseKeyShare(ssl, (word16)group_id)) != WOLFSSL_SUCCESS) {
        wolf_err("wolfSSL_UseKeyShare", rc, err, errlen);
        return -1;
    }
    if (wolfSSL_connect(ssl) != WOLFSSL_SUCCESS) {
        wolf_err("handshake", wolfSSL_get_error(ssl, 0), err, errlen);
        return -1;
    }
    return 0;
}

void hs_lib_info(char *group, size_t glen, char *version, size_t vlen)
{
    const char *g = ssl ? wolfSSL_get_curve_name(ssl) : NULL;
    snprintf(group, glen, "%s", g ? g : "");
    snprintf(version, vlen, "%s", ssl ? wolfSSL_get_version(ssl) : "");
}

int hs_lib_write(const void *buf, size_t len, char *err, size_t errlen)
{
    size_t done = 0;
    while (done < len) {
        int n = wolfSSL_write(ssl, (const char *)buf + done, (int)(len - done));
        if (n <= 0) {
            wolf_err("wolfSSL_write", wolfSSL_get_error(ssl, n), err, errlen);
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
        int n = wolfSSL_read(ssl, buf, sizeof(buf)), e;
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
        e = wolfSSL_get_error(ssl, n);
        /* close_notify, or the server closing TCP after its response */
        if (e == WOLFSSL_ERROR_ZERO_RETURN || ((e == SOCKET_PEER_CLOSED_E || e == SOCKET_ERROR_E) && total > 0))
            return total;
        wolf_err("wolfSSL_read", e, err, errlen);
        return -1;
    }
}

void hs_lib_close(void)
{
    if (!ssl) return;
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    ssl = NULL;
}

void hs_lib_teardown(void)
{
    wolfSSL_CTX_free(ctx);
    ctx = NULL;
    wolfSSL_Cleanup();
}
