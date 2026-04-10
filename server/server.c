/*
 * sshmini-server  –  Secure Remote Command Execution Server
 *
 * Architecture:
 *   - Listens on TCP (default port 4422) wrapped in TLS 1.2+
 *   - One POSIX thread per accepted client (thread-pool friendly)
 *   - Custom binary protocol (see common/protocol.h)
 *   - SHA-256 password authentication via users.db
 *   - Mutex-protected audit log for every session event
 *   - popen() for command execution; streams stdout+stderr to client
 *
 * SSL Algorithm:
 *   - Protocol : TLS 1.2 minimum (TLS 1.3 preferred by OpenSSL)
 *   - Cipher   : TLS_AES_256_GCM_SHA384  (TLS 1.3)
 *                or ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2 fallback)
 *   - Key Exch : ECDHE  (Elliptic Curve Diffie-Hellman Ephemeral)
 *   - Auth     : RSA 2048-bit certificate (self-signed)
 *   - Enc      : AES-256-GCM  (authenticated encryption, 256-bit key)
 *   - MAC/Hash : SHA-384
 *   - Forward Secrecy: YES (ephemeral keys discarded after session)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#include "../common/protocol.h"
#include "../common/utils.h"
#include "auth.h"

/* ─── Configuration ───────────────────────────────────── */
#define CERT_FILE    "certs/server.crt"
#define KEY_FILE     "certs/server.key"
#define LOG_FILE     "audit.log"
#define BACKLOG      16
#define MAX_CLIENTS  15   /* hard cap on simultaneous connections */

/* ─── ANSI colours for terminal output ───────────────── */
#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_RED    "\033[0;31m"
#define C_GREEN  "\033[0;32m"
#define C_YELLOW "\033[0;33m"
#define C_CYAN   "\033[0;36m"
#define C_GREY   "\033[0;90m"

/* ─── Connection table entry ──────────────────────────── */
typedef struct {
    int      active;
    uint32_t session_id;
    char     ip[INET_ADDRSTRLEN];
    int      port;
    char     username[MAX_USERNAME];
    time_t   connected_at;
} conn_entry_t;

static conn_entry_t  g_conns[MAX_CLIENTS];
static pthread_mutex_t g_conn_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ─── Register a new connection slot ─────────────────── */
static int conn_add(uint32_t sid, const char *ip, int port) {
    pthread_mutex_lock(&g_conn_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_conns[i].active) {
            g_conns[i].active       = 1;
            g_conns[i].session_id   = sid;
            g_conns[i].port         = port;
            g_conns[i].connected_at = time(NULL);
            strncpy(g_conns[i].ip, ip, INET_ADDRSTRLEN - 1);
            g_conns[i].username[0]  = '\0';
            pthread_mutex_unlock(&g_conn_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&g_conn_mutex);
    return -1;   /* table full */
}

/* ─── Update username once authenticated ─────────────── */
static void conn_set_user(uint32_t sid, const char *username) {
    pthread_mutex_lock(&g_conn_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_conns[i].active && g_conns[i].session_id == sid) {
            strncpy(g_conns[i].username, username, MAX_USERNAME - 1);
            break;
        }
    }
    pthread_mutex_unlock(&g_conn_mutex);
}

/* ─── Remove a connection slot ────────────────────────── */
static void conn_remove(uint32_t sid) {
    pthread_mutex_lock(&g_conn_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_conns[i].active && g_conns[i].session_id == sid) {
            memset(&g_conns[i], 0, sizeof(g_conns[i]));
            break;
        }
    }
    pthread_mutex_unlock(&g_conn_mutex);
}

/* ─── Count active connections (caller holds no lock) ── */
static int conn_count(void) {
    pthread_mutex_lock(&g_conn_mutex);
    int n = 0;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_conns[i].active) n++;
    pthread_mutex_unlock(&g_conn_mutex);
    return n;
}

/* ─── Print connection table to stdout ───────────────── */
static void print_conn_table(void) {
    pthread_mutex_lock(&g_conn_mutex);

    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (g_conns[i].active) count++;

    printf("\n%s┌─────────────────────────────────────────────────────────────────────┐%s\n", C_CYAN, C_RESET);
    printf("%s│%s  Active Connections: %s%d / %d%s%-41s%s│%s\n",
           C_CYAN, C_RESET, C_BOLD, count, MAX_CLIENTS, C_RESET, "", C_CYAN, C_RESET);
    printf("%s├──────────┬──────────────────┬───────┬──────────────┬────────────────┤%s\n", C_CYAN, C_RESET);
    printf("%s│%s %-8s %s│%s %-16s %s│%s %-5s %s│%s %-12s %s│%s %-14s %s│%s\n",
           C_CYAN, C_GREY, "SID",
           C_CYAN, C_GREY, "IP Address",
           C_CYAN, C_GREY, "Port",
           C_CYAN, C_GREY, "User",
           C_CYAN, C_GREY, "Duration",
           C_CYAN, C_RESET);
    printf("%s├──────────┼──────────────────┼───────┼──────────────┼────────────────┤%s\n", C_CYAN, C_RESET);

    time_t now = time(NULL);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_conns[i].active) continue;
        long secs = (long)(now - g_conns[i].connected_at);
        char dur[32];
        if (secs < 60)
            snprintf(dur, sizeof(dur), "%lds", secs);
        else if (secs < 3600)
            snprintf(dur, sizeof(dur), "%ldm %lds", secs/60, secs%60);
        else
            snprintf(dur, sizeof(dur), "%ldh %ldm", secs/3600, (secs%3600)/60);

        const char *user = g_conns[i].username[0] ? g_conns[i].username : C_YELLOW "(authing)" C_RESET;
        printf("%s│%s %s%08X%s %s│%s %-16s %s│%s %-5d %s│%s %-12s %s│%s %-14s %s│%s\n",
               C_CYAN, C_RESET,
               C_GREEN, g_conns[i].session_id, C_RESET,
               C_CYAN, C_RESET, g_conns[i].ip,
               C_CYAN, C_RESET, g_conns[i].port,
               C_CYAN, C_RESET, user,
               C_CYAN, C_RESET, dur,
               C_CYAN, C_RESET);
    }

    if (count == 0)
        printf("%s│%s  %-66s %s│%s\n", C_CYAN, C_GREY, "No active connections.", C_CYAN, C_RESET);

    printf("%s└──────────┴──────────────────┴───────┴──────────────┴────────────────┘%s\n\n", C_CYAN, C_RESET);
    fflush(stdout);

    pthread_mutex_unlock(&g_conn_mutex);
}

/* ─── Blocked commands (basic safety list) ───────────────*/
static const char *BLOCKED[] = {
    "rm -rf /", "mkfs", "dd if=/dev/zero of=/dev/",
    ":(){:|:&};:", NULL
};

static int is_blocked(const char *cmd) {
    for (int i = 0; BLOCKED[i]; i++)
        if (strstr(cmd, BLOCKED[i])) return 1;
    return 0;
}

/* ─── Per-client thread arg ───────────────────────────── */
typedef struct {
    int      fd;
    SSL     *ssl;
    SSL_CTX *ctx;
    struct sockaddr_in peer;
    uint32_t session_id;
} client_args_t;

/* ─── Audit helper ────────────────────────────────────── */
static void audit(uint32_t sid, const char *user, const char *peer_ip,
                  const char *event, const char *detail) {
    log_info("[SID=%08X][%s@%s] %s: %s", sid, user ? user : "-",
             peer_ip ? peer_ip : "-", event, detail ? detail : "");
}

/* ─── Command execution ───────────────────────────────── */
static int run_command(SSL *ssl, uint32_t sid, const char *cmd) {
    /* Redirect stderr to stdout */
    char full_cmd[MAX_CMD_LEN + 32];
    snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);

    FILE *fp = popen(full_cmd, "r");
    if (!fp) {
        const char *err = "Failed to execute command\n";
        send_msg(ssl, MSG_OUTPUT, sid, err, (uint16_t)strlen(err));
        send_msg(ssl, MSG_EXIT_CODE, sid, "\xFF", 1);
        return -1;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (send_msg(ssl, MSG_OUTPUT, sid, buf, (uint16_t)n) < 0)
            break;
    }

    int status = pclose(fp);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    uint8_t ec = (uint8_t)(exit_code & 0xFF);
    send_msg(ssl, MSG_EXIT_CODE, sid, &ec, 1);
    return exit_code;
}

/* ─── Per-client handler thread ───────────────────────── */
static void *client_thread(void *arg) {
    client_args_t *ca = (client_args_t *)arg;
    SSL           *ssl = ca->ssl;
    uint32_t       sid = ca->session_id;
    char           peer_ip[INET_ADDRSTRLEN];
    char           username[MAX_USERNAME];
    int            peer_port = ntohs(ca->peer.sin_port);

    inet_ntop(AF_INET, &ca->peer.sin_addr, peer_ip, sizeof(peer_ip));

    /* Register in connection table */
    conn_add(sid, peer_ip, peer_port);

    memset(username, 0, sizeof(username));
    int authenticated = 0;

    /* ── TLS handshake ───────────────────────────────── */
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        audit(sid, NULL, peer_ip, "TLS_HANDSHAKE_FAIL", "");
        goto cleanup;
    }
    audit(sid, NULL, peer_ip, "TLS_CONNECT", SSL_get_cipher(ssl));

    /* ── Authentication phase (max 3 attempts) ────────── */
    for (int attempt = 0; attempt < 3 && !authenticated; attempt++) {
        msg_header_t hdr;
        char payload[MAX_USERNAME + MAX_PASSWORD + 2];
        memset(payload, 0, sizeof(payload));

        if (recv_msg(ssl, &hdr, payload, sizeof(payload) - 1) < 0) {
            audit(sid, NULL, peer_ip, "RECV_ERROR", "during auth");
            goto cleanup;
        }
        if (hdr.type != MSG_AUTH_REQ) {
            audit(sid, NULL, peer_ip, "PROTO_ERROR", "expected AUTH_REQ");
            goto cleanup;
        }

        const char *recv_user = payload;
        const char *recv_pass = payload + strlen(recv_user) + 1;

        if (auth_verify(recv_user, recv_pass)) {
            strncpy(username, recv_user, MAX_USERNAME - 1);
            send_msg(ssl, MSG_AUTH_OK, sid, "OK", 2);
            authenticated = 1;
            conn_set_user(sid, username);
            audit(sid, username, peer_ip, "AUTH_SUCCESS", "");

            /* Print updated table after successful login */
            printf("%s[+]%s %s%s%s authenticated from %s%s:%d%s [SID=%s%08X%s]\n",
                   C_GREEN, C_RESET, C_BOLD, username, C_RESET,
                   C_CYAN, peer_ip, peer_port, C_RESET,
                   C_GREEN, sid, C_RESET);
            print_conn_table();
        } else {
            send_msg(ssl, MSG_AUTH_FAIL, sid, "FAIL", 4);
            audit(sid, recv_user, peer_ip, "AUTH_FAIL",
                  attempt < 2 ? "retry" : "max attempts");
            printf("%s[-]%s Auth failure for '%s%s%s' from %s:%d (attempt %d/3)\n",
                   C_RED, C_RESET, C_BOLD, recv_user, C_RESET,
                   peer_ip, peer_port, attempt + 1);
        }
    }

    if (!authenticated) goto cleanup;

    /* ── Command loop ─────────────────────────────────── */
    while (1) {
        msg_header_t hdr;
        char cmd_buf[MAX_CMD_LEN + 1];
        memset(cmd_buf, 0, sizeof(cmd_buf));

        if (recv_msg(ssl, &hdr, cmd_buf, MAX_CMD_LEN) < 0) {
            audit(sid, username, peer_ip, "DISCONNECT", "recv error");
            break;
        }

        if (hdr.type == MSG_BYE) {
            audit(sid, username, peer_ip, "DISCONNECT", "client bye");
            break;
        }
        if (hdr.type == MSG_PING) {
            send_msg(ssl, MSG_PONG, sid, NULL, 0);
            continue;
        }
        if (hdr.type != MSG_CMD) {
            audit(sid, username, peer_ip, "PROTO_ERROR", "unexpected msg type");
            break;
        }

        if (is_blocked(cmd_buf)) {
            const char *denied = "Command blocked by server policy\n";
            send_msg(ssl, MSG_OUTPUT, sid, denied, (uint16_t)strlen(denied));
            uint8_t ec = 1;
            send_msg(ssl, MSG_EXIT_CODE, sid, &ec, 1);
            audit(sid, username, peer_ip, "CMD_BLOCKED", cmd_buf);
            continue;
        }

        audit(sid, username, peer_ip, "CMD_EXEC", cmd_buf);
        run_command(ssl, sid, cmd_buf);
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(ca->fd);

    /* Remove from table and print updated state */
    conn_remove(sid);
    printf("%s[x]%s %s%s%s disconnected from %s%s:%d%s [SID=%s%08X%s] — %s%d%s client(s) remaining\n",
           C_YELLOW, C_RESET, C_BOLD,
           username[0] ? username : "(unauthed)", C_RESET,
           C_CYAN, peer_ip, peer_port, C_RESET,
           C_GREEN, sid, C_RESET,
           C_BOLD, conn_count(), C_RESET);
    print_conn_table();

    free(ca);
    return NULL;
}

/* ─── Main ────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    int port = PORT_DEFAULT;
    if (argc >= 2) port = atoi(argv[1]);

    /* Ignore SIGPIPE so broken connections don't crash server */
    signal(SIGPIPE, SIG_IGN);

    log_set_file(LOG_FILE);
    log_info("sshmini-server starting on port %d", port);
    log_info("Audit log: %s | Users DB: %s", LOG_FILE, USERS_DB);

    /* Init OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = create_server_ctx(CERT_FILE, KEY_FILE);
    if (!ctx) { log_error("Failed to create SSL context"); return 1; }

    /* Create listening socket */
    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(srv_fd, BACKLOG) < 0) {
        perror("listen"); return 1;
    }

    /* ── Startup banner ──────────────────────────────── */
    printf("\n%s╔═══════════════════════════════════════════════════╗%s\n", C_CYAN, C_RESET);
    printf("%s║%s  %ssshmini-server%s — Secure Remote Command Execution %s║%s\n", C_CYAN, C_RESET, C_BOLD, C_RESET, C_CYAN, C_RESET);
    printf("%s╠═══════════════════════════════════════════════════╣%s\n", C_CYAN, C_RESET);
    printf("%s║%s  Port        : %s%d%s%-26s%s     ║%s\n", C_CYAN, C_RESET, C_GREEN, port, C_RESET, "", C_CYAN, C_RESET);
    printf("%s║%s  Max clients : %s%d%s%-26s%s       ║%s\n", C_CYAN, C_RESET, C_GREEN, MAX_CLIENTS, C_RESET, "", C_CYAN, C_RESET);
    printf("%s║%s  Protocol    : %sTLS 1.2 / 1.3%s%-20s%s  ║%s\n", C_CYAN, C_RESET, C_GREEN, C_RESET, "", C_CYAN, C_RESET);
    printf("%s║%s  Cipher      : %sAES-256-GCM-SHA384%s%-15s%s  ║%s\n", C_CYAN, C_RESET, C_GREEN, C_RESET, "", C_CYAN, C_RESET);
    printf("%s║%s  Key Exch    : %sECDHE (Forward Secrecy)%s%-9s%s   ║%s\n", C_CYAN, C_RESET, C_GREEN, C_RESET, "", C_CYAN, C_RESET);
    printf("%s║%s  Auth        : %sSHA-256 hashed passwords%s%-9s%s  ║%s\n", C_CYAN, C_RESET, C_GREEN, C_RESET, "", C_CYAN, C_RESET);
    printf("%s║%s  Audit log   : %s%s%s%-26s%s║%s\n", C_CYAN, C_RESET, C_GREEN, LOG_FILE, C_RESET, "", C_CYAN, C_RESET);
    printf("%s╚═══════════════════════════════════════════════════╝%s\n\n", C_CYAN, C_RESET);
    fflush(stdout);

    while (1) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int cli_fd = accept(srv_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (cli_fd < 0) {
            log_warn("accept() failed: %s", strerror(errno));
            continue;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, ip, sizeof(ip));
        int peer_port = ntohs(peer_addr.sin_port);

        /* ── Enforce MAX_CLIENTS limit ───────────────── */
        if (conn_count() >= MAX_CLIENTS) {
            printf("%s[!]%s Connection from %s%s:%d%s %sREJECTED%s — server at capacity (%d/%d)\n",
                   C_RED, C_RESET, C_CYAN, ip, peer_port, C_RESET,
                   C_RED, C_RESET, MAX_CLIENTS, MAX_CLIENTS);
            log_warn("Connection from %s:%d rejected — at capacity (%d/%d)",
                     ip, peer_port, MAX_CLIENTS, MAX_CLIENTS);
            close(cli_fd);
            continue;
        }

        /* Wrap in SSL */
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cli_fd);

        /* Build thread args */
        client_args_t *ca = calloc(1, sizeof(*ca));
        ca->fd         = cli_fd;
        ca->ssl        = ssl;
        ca->ctx        = ctx;
        ca->peer       = peer_addr;
        ca->session_id = gen_session_id();

        /* Print incoming connection immediately */
        printf("%s[>]%s Incoming connection from %s%s:%d%s [SID=%s%08X%s] — %s%d%s/%d active\n",
               C_GREEN, C_RESET,
               C_CYAN, ip, peer_port, C_RESET,
               C_GREEN, ca->session_id, C_RESET,
               C_BOLD, conn_count() + 1, C_RESET, MAX_CLIENTS);
        fflush(stdout);
        log_info("New connection from %s:%d [SID=%08X] active=%d",
                 ip, peer_port, ca->session_id, conn_count() + 1);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, client_thread, ca) != 0) {
            log_error("pthread_create failed");
            SSL_free(ssl);
            close(cli_fd);
            free(ca);
        }
        pthread_attr_destroy(&attr);
    }

    SSL_CTX_free(ctx);
    close(srv_fd);
    return 0;
}
