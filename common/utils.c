#include "utils.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ─── Logging ─────────────────────────────────────────── */
static FILE        *g_log_fp   = NULL;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void _log(const char *level, const char *fmt, va_list ap) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    pthread_mutex_lock(&g_log_mutex);
    FILE *dest = g_log_fp ? g_log_fp : stderr;
    fprintf(dest, "[%s] [%s] ", timebuf, level);
    vfprintf(dest, fmt, ap);
    fprintf(dest, "\n");
    fflush(dest);
    pthread_mutex_unlock(&g_log_mutex);
}

void log_info (const char *fmt, ...) { va_list ap; va_start(ap,fmt); _log("INFO ", fmt, ap); va_end(ap); }
void log_warn (const char *fmt, ...) { va_list ap; va_start(ap,fmt); _log("WARN ", fmt, ap); va_end(ap); }
void log_error(const char *fmt, ...) { va_list ap; va_start(ap,fmt); _log("ERROR", fmt, ap); va_end(ap); }
void log_debug(const char *fmt, ...) { va_list ap; va_start(ap,fmt); _log("DEBUG", fmt, ap); va_end(ap); }

void log_set_file(const char *path) {
    g_log_fp = fopen(path, "a");
    if (!g_log_fp) { perror("log_set_file"); g_log_fp = NULL; }
}

/* ─── SSL context helpers ─────────────────────────────── */
SSL_CTX *create_server_ctx(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file (ctx, key,  SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        log_error("Private key does not match certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SSL_CTX *create_client_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return NULL; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    /* For demo / self-signed: skip peer verify.
       In production: SSL_CTX_set_verify + load CA cert */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

/* ─── Message I/O ─────────────────────────────────────── */
int send_msg(SSL *ssl, msg_type_t type, uint32_t session_id,
             const void *payload, uint16_t len) {
    msg_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.type        = (uint8_t)type;
    hdr.flags       = 0;
    hdr.payload_len = htons(len);
    hdr.session_id  = htonl(session_id);

    /* send header */
    int n = SSL_write(ssl, &hdr, HEADER_SIZE);
    if (n != HEADER_SIZE) return -1;

    /* send payload if any */
    if (len > 0 && payload) {
        n = SSL_write(ssl, payload, len);
        if (n != (int)len) return -1;
    }
    return 0;
}

int recv_msg(SSL *ssl, msg_header_t *hdr, void *payload_buf, uint16_t buf_size) {
    /* receive header */
    int n = SSL_read(ssl, hdr, HEADER_SIZE);
    if (n <= 0) return -1;
    if (n != HEADER_SIZE) return -1;

    hdr->payload_len = ntohs(hdr->payload_len);
    hdr->session_id  = ntohl(hdr->session_id);

    if (hdr->payload_len == 0) return 0;
    if (hdr->payload_len > buf_size) {
        log_warn("recv_msg: payload too large (%u > %u)", hdr->payload_len, buf_size);
        return -1;
    }

    /* receive payload */
    uint16_t received = 0;
    uint8_t *buf = (uint8_t *)payload_buf;
    while (received < hdr->payload_len) {
        n = SSL_read(ssl, buf + received, hdr->payload_len - received);
        if (n <= 0) return -1;
        received += n;
    }
    return 0;
}

/* ─── Session ID ──────────────────────────────────────── */
uint32_t gen_session_id(void) {
    static uint32_t counter = 0;
    return (uint32_t)time(NULL) ^ (++counter << 16);
}
