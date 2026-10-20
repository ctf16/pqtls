/* hsloop: time many full TLS 1.3 handshakes in one client process.
 *
 * hsloop.c holds everything that doesn't depend on the TLS library: options,
 * TCP connect, timing, the loop and the CSV output. Each library adapter
 * (openssl.c, wolfssl.c, s2n.c) implements the functions below, keeping its
 * current connection in file-static state. Every handshake uses a new TCP
 * connection and a new connection object from one shared, reused context;
 * session resumption is off, so each handshake is a full one. */
#ifndef HSLOOP_H
#define HSLOOP_H

#include <stddef.h>

typedef struct {
    const char *host, *port;   /* server address */
    const char *group;         /* OpenSSL TLS group name, e.g. MLKEM768 */
    const char *ca;            /* CA file (PEM) to verify the server */
    const char *cert, *key;    /* optional client certificate and key (PEM) */
    const char *policy;        /* s2n-tls security policy (s2n only) */
    const char *sni;           /* server name to send and verify */
    const char *out;           /* CSV output file */
    int count, warmup;         /* timed and untimed handshakes */
    int timeout;               /* socket send/receive timeout, seconds */
} hs_opts;

/* Adapter interface. Functions return 0 on success; on failure they write a
 * one-line reason to err (size errlen). */
extern const char *hs_lib_name;
int  hs_lib_setup(const hs_opts *o, char *err, size_t errlen);
int  hs_lib_handshake(int fd, const hs_opts *o, char *err, size_t errlen);
/* after a handshake: negotiated group and protocol version ("" if unknown) */
void hs_lib_info(char *group, size_t glen, char *version, size_t vlen);
int  hs_lib_write(const void *buf, size_t len, char *err, size_t errlen);
/* read until the server closes; returns bytes read or -1. The first bytes go to
 * head (size headlen, NUL-terminated) so the caller can check the response. */
long hs_lib_read_all(char *head, size_t headlen, char *err, size_t errlen);
void hs_lib_close(void);       /* send close_notify (best effort), free the connection */
void hs_lib_teardown(void);

/* group name check shared by the adapters' callers */
int hs_group_matches(const char *requested, const char *negotiated);

#endif
