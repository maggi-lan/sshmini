#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

/* ─── Magic & Version ─────────────────────────────────── */
#define PROTO_MAGIC   0xSSEC  /* replaced below as numeric */
#define PROTO_VERSION 0x01

/* Numeric magic for wire format */
#define MAGIC_BYTES   "\x53\x45\x43\x01"   /* "SEC\x01" */
#define MAGIC_LEN     4

/* ─── Message Types ───────────────────────────────────── */
typedef enum {
    MSG_AUTH_REQ   = 0x10,   /* client → server: auth request   */
    MSG_AUTH_OK    = 0x11,   /* server → client: auth success    */
    MSG_AUTH_FAIL  = 0x12,   /* server → client: auth failure    */
    MSG_CMD        = 0x20,   /* client → server: command string  */
    MSG_OUTPUT     = 0x21,   /* server → client: command output  */
    MSG_EXIT_CODE  = 0x22,   /* server → client: exit status     */
    MSG_PING       = 0x30,   /* keepalive ping                   */
    MSG_PONG       = 0x31,   /* keepalive pong                   */
    MSG_BYE        = 0xFF,   /* graceful disconnect              */
} msg_type_t;

/* ─── Wire Header (fixed 8 bytes) ─────────────────────── */
/*
 *  0        1        2        3
 *  +--------+--------+--------+--------+
 *  | type   | flags  |    payload_len   |
 *  +--------+--------+--------+--------+
 *  |            session_id             |
 *  +--------+--------+--------+--------+
 *
 *  type        : msg_type_t (1 byte)
 *  flags       : reserved  (1 byte, set to 0)
 *  payload_len : uint16_t big-endian  (2 bytes)
 *  session_id  : uint32_t big-endian  (4 bytes)
 */
#define HEADER_SIZE  8
#define MAX_PAYLOAD  65535

typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  flags;
    uint16_t payload_len;   /* network byte order */
    uint32_t session_id;    /* network byte order */
} msg_header_t;

/* ─── Auth sub-structure (inside MSG_AUTH_REQ payload) ── */
/*  username\0password\0  – null-terminated, max 256 each  */
#define MAX_USERNAME 256
#define MAX_PASSWORD 256

/* ─── Limits ──────────────────────────────────────────── */
#define MAX_CMD_LEN  4096
#define MAX_OUT_LEN  65535
#define PORT_DEFAULT 4422

#endif /* PROTOCOL_H */
