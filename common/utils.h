#ifndef UTILS_H
#define UTILS_H

#include <openssl/ssl.h>
#include <stdint.h>
#include "protocol.h"

/* ─── Logging ─────────────────────────────────────────── */
void log_info (const char *fmt, ...);
void log_warn (const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_debug(const char *fmt, ...);
void log_set_file(const char *path);   /* audit log */

/* ─── SSL helpers ─────────────────────────────────────── */
SSL_CTX *create_server_ctx(const char *cert, const char *key);
SSL_CTX *create_client_ctx(void);          /* no cert verification for self-signed demo */

/* ─── Message I/O over SSL ───────────────────────────── */
int  send_msg(SSL *ssl, msg_type_t type, uint32_t session_id,
              const void *payload, uint16_t len);
int  recv_msg(SSL *ssl, msg_header_t *hdr, void *payload_buf, uint16_t buf_size);

/* ─── Misc ────────────────────────────────────────────── */
uint32_t gen_session_id(void);

#endif /* UTILS_H */
