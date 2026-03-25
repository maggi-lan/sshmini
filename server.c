#include "common.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
	SSL *ssl;
	int client_fd;
} client_t;

pthread_mutex_t log_mutex;

int authenticate(const char *user, const char *pass) {
	FILE *f = fopen("users.txt", "r");
	if (!f)
		return 0;

	char u[100], p[100];
	while (fscanf(f, "%s %s", u, p) != EOF) {
		if (strcmp(u, user) == 0 && strcmp(p, pass) == 0) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

void log_command(const char *user, const char *cmd) {
	pthread_mutex_lock(&log_mutex);
	FILE *f = fopen("audit.log", "a");
	if (f) {
		fprintf(f, "USER: %s CMD: %s\n", user, cmd);
		fclose(f);
	}
	pthread_mutex_unlock(&log_mutex);
}

void *handle_client(void *arg) {
	client_t *client = (client_t *)arg;
	SSL *ssl = client->ssl;

	char buffer[BUFFER_SIZE];
	char user[100], pass[100];

	// AUTH
	int bytes = SSL_read(ssl, buffer, sizeof(buffer));
	buffer[bytes] = '\0';

	sscanf(buffer, "AUTH %s %s", user, pass);

	if (!authenticate(user, pass)) {
		SSL_write(ssl, "FAIL\n", 5);
		goto cleanup;
	}

	SSL_write(ssl, "OK\n", 3);

	// COMMAND LOOP
	while (1) {
		bytes = SSL_read(ssl, buffer, sizeof(buffer));
		if (bytes <= 0)
			break;

		buffer[bytes] = '\0';

		if (strncmp(buffer, "CMD", 3) == 0) {
			char *cmd = buffer + 4;

			log_command(user, cmd);

			// capture stderr too
			char full_cmd[BUFFER_SIZE];
			snprintf(full_cmd, sizeof(full_cmd), "%s 2>&1", cmd);

			FILE *fp = popen(full_cmd, "r");
			if (!fp)
				continue;

			char output[BUFFER_SIZE];
			int len = fread(output, 1, sizeof(output) - 1, fp);
			output[len] = '\0';

			int status = pclose(fp);
			int exit_code = WEXITSTATUS(status);

			// NEW protocol: include exit code
			char header[100];
			sprintf(header, "OUTPUT %d %d\n", len, exit_code);

			SSL_write(ssl, header, strlen(header));

			if (len > 0)
				SSL_write(ssl, output, len);

			SSL_write(ssl, "END\n", 4);
		}
	}

cleanup:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client->client_fd);
	free(client);
	return NULL;
}

int main() {
	SSL_library_init();
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

	SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in addr = {.sin_family = AF_INET,
	                           .sin_port = htons(PORT),
	                           .sin_addr.s_addr = INADDR_ANY};

	bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
	listen(server_fd, 10);

	pthread_mutex_init(&log_mutex, NULL);

	printf("Server running on port %d\n", PORT);

	while (1) {
		int client_fd = accept(server_fd, NULL, NULL);

		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client_fd);

		if (SSL_accept(ssl) <= 0) {
			SSL_free(ssl);
			close(client_fd);
			continue;
		}

		client_t *client = malloc(sizeof(client_t));
		client->ssl = ssl;
		client->client_fd = client_fd;

		pthread_t tid;
		pthread_create(&tid, NULL, handle_client, client);
		pthread_detach(tid);
	}

	close(server_fd);
	SSL_CTX_free(ctx);
}
