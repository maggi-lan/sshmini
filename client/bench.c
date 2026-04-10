/*
 * bench  –  Performance benchmark for sshmini-server
 *
 * Spawns N concurrent clients, each running M commands,
 * measures latency and throughput.
 *
 * Usage:
 *   ./bench <host> [port] [num_clients] [cmds_per_client]
 *
 * Example:
 *   ./bench 127.0.0.1 4422 10 20
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../common/protocol.h"
#include "../common/utils.h"

/* ─── Config (edit or pass via args) ─────────────────── */
#define BENCH_USER "benchuser"
#define BENCH_PASS "benchpass"
#define BENCH_CMD  "echo hello_world"

typedef struct {
    const char *host;
    int         port;
    int         cmds;
    int         client_id;
    /* results */
    double      total_ms;
    int         errors;
    int         success;
} bench_args_t;

static SSL_CTX *g_ctx = NULL;

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void *bench_client(void *arg) {
    bench_args_t *ba = (bench_args_t *)arg;

    /* connect */
    struct addrinfo hints = {0}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", ba->port);
    if (getaddrinfo(ba->host, portstr, &hints, &res) != 0) { ba->errors++; return NULL; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        ba->errors++; freeaddrinfo(res); close(fd); return NULL;
    }
    freeaddrinfo(res);

    SSL *ssl = SSL_new(g_ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) { ba->errors++; SSL_free(ssl); close(fd); return NULL; }

    /* auth */
    char payload[MAX_USERNAME + MAX_PASSWORD + 2];
    size_t ul = strlen(BENCH_USER) + 1, pl = strlen(BENCH_PASS) + 1;
    memcpy(payload, BENCH_USER, ul);
    memcpy(payload + ul, BENCH_PASS, pl);
    uint32_t sid = gen_session_id();
    send_msg(ssl, MSG_AUTH_REQ, sid, payload, (uint16_t)(ul + pl));

    msg_header_t hdr;
    char resp[64] = {0};
    if (recv_msg(ssl, &hdr, resp, sizeof(resp)-1) < 0 || hdr.type != MSG_AUTH_OK) {
        ba->errors++; SSL_shutdown(ssl); SSL_free(ssl); close(fd); return NULL;
    }

    /* run commands */
    double t0 = now_ms();
    for (int i = 0; i < ba->cmds; i++) {
        send_msg(ssl, MSG_CMD, sid, BENCH_CMD, (uint16_t)strlen(BENCH_CMD));
        while (1) {
            char out[MAX_OUT_LEN + 1] = {0};
            if (recv_msg(ssl, &hdr, out, MAX_OUT_LEN) < 0) { ba->errors++; goto done; }
            if (hdr.type == MSG_EXIT_CODE) { ba->success++; break; }
        }
    }
done:
    ba->total_ms = now_ms() - t0;
    send_msg(ssl, MSG_BYE, sid, NULL, 0);
    SSL_shutdown(ssl); SSL_free(ssl); close(fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    const char *host    = argc >= 2 ? argv[1] : "127.0.0.1";
    int port            = argc >= 3 ? atoi(argv[2]) : PORT_DEFAULT;
    int num_clients     = argc >= 4 ? atoi(argv[3]) : 5;
    int cmds_per_client = argc >= 5 ? atoi(argv[4]) : 10;

    printf("=== sshmini Benchmark ===\n");
    printf("Server : %s:%d\n", host, port);
    printf("Clients: %d\n", num_clients);
    printf("Cmds/cl: %d\n", cmds_per_client);
    printf("Command: %s\n\n", BENCH_CMD);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ctx = create_client_ctx();
    if (!g_ctx) return 1;

    bench_args_t *args = calloc(num_clients, sizeof(*args));
    pthread_t    *tids  = calloc(num_clients, sizeof(*tids));

    double wall_start = now_ms();

    for (int i = 0; i < num_clients; i++) {
        args[i].host      = host;
        args[i].port      = port;
        args[i].cmds      = cmds_per_client;
        args[i].client_id = i;
        pthread_create(&tids[i], NULL, bench_client, &args[i]);
    }

    for (int i = 0; i < num_clients; i++)
        pthread_join(tids[i], NULL);

    double wall_ms = now_ms() - wall_start;

    /* ── Aggregate stats ──────────────────────────────── */
    int    total_ok  = 0, total_err = 0;
    double total_ms_sum = 0;
    for (int i = 0; i < num_clients; i++) {
        total_ok     += args[i].success;
        total_err    += args[i].errors;
        total_ms_sum += args[i].total_ms;
    }

    int expected = num_clients * cmds_per_client;
    double avg_lat_ms  = total_ok > 0 ? (total_ms_sum / num_clients / cmds_per_client) : 0;
    double throughput  = total_ok / (wall_ms / 1000.0);

    printf("─────────────────────────────────────────\n");
    printf("Wall clock time    : %.1f ms\n", wall_ms);
    printf("Commands attempted : %d\n", expected);
    printf("Commands succeeded : %d\n", total_ok);
    printf("Errors             : %d\n", total_err);
    printf("Avg latency/cmd    : %.2f ms\n", avg_lat_ms);
    printf("Throughput         : %.1f cmd/s\n", throughput);
    printf("─────────────────────────────────────────\n");

    free(args); free(tids);
    SSL_CTX_free(g_ctx);
    return 0;
}
