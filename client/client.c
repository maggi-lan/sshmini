/*
 * sshmini-client  –  Secure Remote Command Execution Client
 *
 * Usage:
 *   ./sshmini-client <host> [port]
 *
 * The client connects over TLS, authenticates, then enters an
 * interactive shell loop where commands are sent to the server
 * and output is printed locally.  Type 'exit' or 'quit' to
 * disconnect gracefully.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/protocol.h"
#include "../common/utils.h"

/* ─── Helpers ─────────────────────────────────────────── */
static void read_password(const char *prompt, char *buf, size_t len) {
    struct termios old, noecho;
    tcgetattr(STDIN_FILENO, &old);
    noecho = old;
    noecho.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &noecho);
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)len, stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
}

/* ─── Resolve host to IPv4 ────────────────────────────── */
static int resolve(const char *host, struct sockaddr_in *out) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
    *out = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}

/* ─── Banner ──────────────────────────────────────────── */
static void print_banner(void) {
    printf("\033[1;32m");
    printf("  _____ _____ _    _ __  __ _       _ \n");
    printf(" / ____/ ____| |  | |  \\/  (_)     (_)\n");
    printf("| (___| (___ | |__| | \\  / |_ _ __  _ \n");
    printf(" \\___ \\\\___ \\|  __  | |\\/| | | '_ \\| |\n");
    printf(" ____) |___) | |  | | |  | | | | | | |\n");
    printf("|_____/_____/|_|  |_|_|  |_|_|_| |_|_|\n");
    printf("\033[0m");
    printf("\033[0;90m  Secure Remote Command Execution — mini SSH\033[0m\n\n");
}

/* ─── Main ────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host> [port]\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    int port = (argc >= 3) ? atoi(argv[2]) : PORT_DEFAULT;

    print_banner();

    /* ── Resolve & connect ───────────────────────────── */
    struct sockaddr_in srv_addr;
    if (resolve(host, &srv_addr) < 0) {
        fprintf(stderr, "Cannot resolve host: %s\n", host);
        return 1;
    }
    srv_addr.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    printf("\033[0;33m[*]\033[0m Connecting to %s:%d ...\n", host, port);
    if (connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("connect"); close(fd); return 1;
    }

    /* ── TLS wrap ────────────────────────────────────── */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = create_client_ctx();
    if (!ctx) { close(fd); return 1; }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl); SSL_CTX_free(ctx); close(fd);
        return 1;
    }
    printf("\033[0;32m[+]\033[0m TLS connection established (%s)\n",
           SSL_get_cipher(ssl));

    /* ── Get credentials ─────────────────────────────── */
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    printf("\033[0;33mUsername:\033[0m ");
    fflush(stdout);
    if (!fgets(username, sizeof(username), stdin)) goto bye;
    username[strcspn(username, "\r\n")] = '\0';
    read_password("\033[0;33mPassword:\033[0m ", password, sizeof(password));

    /* ── Build AUTH_REQ payload: "user\0pass\0" ──────── */
    {
        char auth_payload[MAX_USERNAME + MAX_PASSWORD + 2];
        size_t ulen = strlen(username) + 1;
        size_t plen = strlen(password) + 1;
        memcpy(auth_payload, username, ulen);
        memcpy(auth_payload + ulen, password, plen);
        memset(password, 0, sizeof(password)); /* wipe */

        uint32_t session_id = gen_session_id();
        if (send_msg(ssl, MSG_AUTH_REQ, session_id,
                     auth_payload, (uint16_t)(ulen + plen)) < 0) {
            fprintf(stderr, "Send auth failed\n"); goto bye;
        }

        msg_header_t hdr;
        char resp[64] = {0};
        if (recv_msg(ssl, &hdr, resp, sizeof(resp) - 1) < 0) {
            fprintf(stderr, "Receive auth response failed\n"); goto bye;
        }
        if (hdr.type == MSG_AUTH_FAIL) {
            printf("\033[0;31m[-]\033[0m Authentication failed.\n");
            goto bye;
        }
        if (hdr.type != MSG_AUTH_OK) {
            printf("\033[0;31m[-]\033[0m Unexpected server response.\n");
            goto bye;
        }

        printf("\033[0;32m[+]\033[0m Authenticated as \033[1m%s\033[0m\n\n",
               username);
        printf("Type commands to execute remotely. Type \033[1mexit\033[0m or \033[1mquit\033[0m to disconnect.\n");
        printf("────────────────────────────────────────────\n");

        /* ── Interactive command loop ──────────────────── */
        char cmd[MAX_CMD_LEN];
        while (1) {
            printf("\033[1;32m%s@%s\033[0m:\033[1;34m~\033[0m$ ", username, host);
            fflush(stdout);

            if (!fgets(cmd, sizeof(cmd), stdin)) break;
            cmd[strcspn(cmd, "\r\n")] = '\0';
            if (strlen(cmd) == 0) continue;
            if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
                send_msg(ssl, MSG_BYE, session_id, NULL, 0);
                printf("Goodbye.\n");
                break;
            }
            /* Send command */
            if (send_msg(ssl, MSG_CMD, session_id,
                         cmd, (uint16_t)strlen(cmd)) < 0) {
                fprintf(stderr, "Connection lost.\n"); break;
            }

            /* Collect output until MSG_EXIT_CODE */
            while (1) {
                msg_header_t ohdr;
                char out[MAX_OUT_LEN + 1];
                memset(out, 0, sizeof(out));
                if (recv_msg(ssl, &ohdr, out, MAX_OUT_LEN) < 0) {
                    fprintf(stderr, "\nConnection lost during output.\n");
                    goto bye;
                }
                if (ohdr.type == MSG_OUTPUT) {
                    fwrite(out, 1, ohdr.payload_len, stdout);
                    fflush(stdout);
                } else if (ohdr.type == MSG_EXIT_CODE) {
                    uint8_t ec = (ohdr.payload_len > 0) ? (uint8_t)out[0] : 0;
                    if (ec != 0)
                        printf("\033[0;31m[exit %d]\033[0m\n", ec);
                    break;
                } else if (ohdr.type == MSG_PONG) {
                    continue;
                } else {
                    break;
                }
            }
        }
    }

bye:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
