/* hsloop driver: options, TCP, timing, the handshake loop and CSV output.
 * Linked with exactly one adapter (openssl.c, wolfssl.c or s2n.c). */
#define _POSIX_C_SOURCE 200809L
#include "hsloop.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#define REQUEST "GET / HTTP/1.0\r\n\r\n"
#define MAX_CONSECUTIVE_FAILURES 10

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage: hsloop-%s --port P --group G --ca CA.pem [options]\n"
        "  --host H        server address (default 127.0.0.1)\n"
        "  --port P        server port\n"
        "  --group G       key-exchange group, OpenSSL name (X25519, P-256, MLKEM768, X25519MLKEM768, ...)\n"
        "  --ca FILE       CA certificate(s) to verify the server (PEM)\n"
        "  --cert FILE     client certificate (PEM), with --key, for mutual TLS\n"
        "  --key FILE      client private key (PEM)\n"
        "  --policy NAME   s2n-tls security policy (s2n only; sets the group)\n"
        "  --sni NAME      server name to send and verify (default localhost)\n"
        "  --count N       timed handshakes (default 100)\n"
        "  --warmup N      untimed handshakes first (default 5)\n"
        "  --timeout S     socket timeout in seconds (default 10)\n"
        "  --out FILE      CSV of the timed handshakes (default: stdout)\n"
        "Prints one summary line: init_ms=... timed=... failed=... group=... version=...\n"
        "Exit status: 0 all handshakes ok, 1 some failed, 2 setup or usage error.\n",
        hs_lib_name);
}

static int parse_args(int argc, char **argv, hs_opts *o)
{
    static const struct option lo[] = {
        {"host", 1, 0, 'H'}, {"port", 1, 0, 'p'}, {"group", 1, 0, 'g'}, {"ca", 1, 0, 'a'},
        {"cert", 1, 0, 'c'}, {"key", 1, 0, 'k'}, {"policy", 1, 0, 'P'}, {"sni", 1, 0, 's'},
        {"count", 1, 0, 'n'}, {"warmup", 1, 0, 'w'}, {"timeout", 1, 0, 't'}, {"out", 1, 0, 'o'},
        {"help", 0, 0, 'h'}, {0, 0, 0, 0}};
    int c;
    memset(o, 0, sizeof(*o));
    o->host = "127.0.0.1"; o->sni = "localhost"; o->count = 100; o->warmup = 5; o->timeout = 10;
    while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (c) {
        case 'H': o->host = optarg; break;
        case 'p': o->port = optarg; break;
        case 'g': o->group = optarg; break;
        case 'a': o->ca = optarg; break;
        case 'c': o->cert = optarg; break;
        case 'k': o->key = optarg; break;
        case 'P': o->policy = optarg; break;
        case 's': o->sni = optarg; break;
        case 'n': o->count = atoi(optarg); break;
        case 'w': o->warmup = atoi(optarg); break;
        case 't': o->timeout = atoi(optarg); break;
        case 'o': o->out = optarg; break;
        case 'h': usage(stdout); exit(0);
        default: usage(stderr); return -1;
        }
    }
    if (!o->port || !o->group || !o->ca || o->count < 0 || o->warmup < 0 || o->timeout <= 0 ||
        (!o->cert) != (!o->key)) {
        usage(stderr);
        return -1;
    }
    return 0;
}

static int tcp_connect(const hs_opts *o, char *err, size_t errlen)
{
    struct addrinfo hints, *res, *ai;
    struct timeval tv;
    int fd = -1, rc;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((rc = getaddrinfo(o->host, o->port, &hints, &res)) != 0) {
        snprintf(err, errlen, "getaddrinfo: %s", gai_strerror(rc));
        return -1;
    }
    tv.tv_sec = o->timeout; tv.tv_usec = 0;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        snprintf(err, errlen, "connect: %s", strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* lower-case letters and digits only, with the NIST curve aliases folded */
static void norm_group(const char *in, char *out, size_t outlen)
{
    char buf[96];
    size_t n = 0;
    for (; *in && n + 1 < sizeof(buf); in++)
        if (isalnum((unsigned char)*in)) buf[n++] = (char)tolower((unsigned char)*in);
    buf[n] = 0;
    if (!strncmp(buf, "prime256v1", 10)) snprintf(out, outlen, "secp256r1%s", buf + 10);
    else if (!strncmp(buf, "p256", 4)) snprintf(out, outlen, "secp256r1%s", buf + 4);
    else if (!strncmp(buf, "p384", 4)) snprintf(out, outlen, "secp384r1%s", buf + 4);
    else if (!strncmp(buf, "p521", 4)) snprintf(out, outlen, "secp521r1%s", buf + 4);
    else snprintf(out, outlen, "%s", buf);
}

int hs_group_matches(const char *requested, const char *negotiated)
{
    char a[96], b[96];
    norm_group(requested, a, sizeof(a));
    norm_group(negotiated, b, sizeof(b));
    return strcmp(a, b) == 0;
}

/* one handshake; fills the five phase times (ms). Returns 0 if it succeeded. */
static int one_handshake(const hs_opts *o, double t[5], char *group, size_t glen,
                         char *version, size_t vlen, char *err, size_t errlen)
{
    char head[64];
    double t0, t1, t2, t3, t4;
    long got;
    int fd;

    group[0] = version[0] = err[0] = 0;
    t0 = now_ms();
    if ((fd = tcp_connect(o, err, errlen)) < 0) return -1;
    t1 = now_ms();
    if (hs_lib_handshake(fd, o, err, errlen) != 0) {
        hs_lib_close();
        close(fd);
        return -1;
    }
    t2 = now_ms();
    hs_lib_info(group, glen, version, vlen);
    if (hs_lib_write(REQUEST, sizeof(REQUEST) - 1, err, errlen) != 0 ||
        (got = hs_lib_read_all(head, sizeof(head), err, errlen)) < 0) {
        hs_lib_close();
        close(fd);
        return -1;
    }
    t3 = now_ms();
    hs_lib_close();
    close(fd);
    t4 = now_ms();
    if (strncmp(head, "HTTP/1.", 7) != 0) {
        snprintf(err, errlen, "no HTTP response (%ld bytes)", got);
        return -1;
    }
    if (group[0] && !hs_group_matches(o->group, group)) {
        snprintf(err, errlen, "negotiated %s, not %s", group, o->group);
        return -1;
    }
    t[0] = t1 - t0; t[1] = t2 - t1; t[2] = t3 - t2; t[3] = t4 - t3; t[4] = t4 - t0;
    return 0;
}

static void csv_field(FILE *f, const char *s)
{
    for (; *s; s++) fputc(*s == ',' || *s == '\n' ? ';' : *s, f);
}

int main(int argc, char **argv)
{
    double start = now_ms(), init_ms, t[5];
    char err[256], group[96], version[32], last_group[96] = "", last_version[32] = "";
    int i, failed = 0, warm_failed = 0, consecutive = 0;
    hs_opts o;
    FILE *out = stdout;

    if (parse_args(argc, argv, &o) != 0) return 2;
    /* a close_notify to a server that already closed must not kill the process */
    signal(SIGPIPE, SIG_IGN);
    if (hs_lib_setup(&o, err, sizeof(err)) != 0) {
        fprintf(stderr, "hsloop-%s: setup failed: %s\n", hs_lib_name, err);
        return 2;
    }
    init_ms = now_ms() - start;
    if (o.out && !(out = fopen(o.out, "w"))) {
        fprintf(stderr, "hsloop-%s: cannot write %s: %s\n", hs_lib_name, o.out, strerror(errno));
        return 2;
    }
    fprintf(out, "iteration,connect_ms,handshake_ms,response_ms,close_ms,total_ms,group,version,ok,error\n");

    for (i = 1; i <= o.warmup + o.count; i++) {
        int timed = i > o.warmup, rc;
        rc = one_handshake(&o, t, group, sizeof(group), version, sizeof(version), err, sizeof(err));
        if (rc == 0) {
            consecutive = 0;
            snprintf(last_group, sizeof(last_group), "%s", group);
            snprintf(last_version, sizeof(last_version), "%s", version);
        } else {
            consecutive++;
            if (timed) failed++; else warm_failed++;
        }
        if (timed) {
            if (rc == 0)
                fprintf(out, "%d,%.3f,%.3f,%.3f,%.3f,%.3f,", i - o.warmup, t[0], t[1], t[2], t[3], t[4]);
            else
                fprintf(out, "%d,,,,,,", i - o.warmup);
            csv_field(out, group);
            fputc(',', out);
            csv_field(out, version);
            fprintf(out, ",%d,", rc == 0);
            csv_field(out, rc == 0 ? "" : err);
            fputc('\n', out);
        }
        if (rc != 0 && consecutive >= MAX_CONSECUTIVE_FAILURES) {
            fprintf(stderr, "hsloop-%s: %d failures in a row, stopping (last: %s)\n",
                    hs_lib_name, consecutive, err);
            /* the timed handshakes not attempted */
            failed += o.warmup + o.count - (i > o.warmup ? i : o.warmup);
            break;
        }
        if (rc != 0) fprintf(stderr, "hsloop-%s: handshake %d failed: %s\n", hs_lib_name, i, err);
    }
    if (out != stdout) fclose(out);
    hs_lib_teardown();
    printf("init_ms=%.3f timed=%d failed=%d warmup_failed=%d group=%s version=%s\n",
           init_ms, o.count, failed, warm_failed, last_group[0] ? last_group : "-",
           last_version[0] ? last_version : "-");
    return failed ? 1 : 0;
}
