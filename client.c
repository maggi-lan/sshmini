#include "common.h"
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int ssl_read_line(SSL *ssl, char *buf, int maxlen) {
	int total = 0;
	char c;
	while (total < maxlen - 1) {
		int n = SSL_read(ssl, &c, 1);
		if (n <= 0)
			return n;
		buf[total++] = c;
		if (c == '\n')
			break;
	}
	buf[total] = '\0';
	return total;
}

int ssl_read_exact(SSL *ssl, char *buf, int len) {
	int total = 0;
	while (total < len) {
		int n = SSL_read(ssl, buf + total, len - total);
		if (n <= 0)
			return n;
		total += n;
	}
	return total;
}

void flush_stdin() {
	int c;
	while ((c = getchar()) != '\n' && c != EOF)
		;
}

int main() {
	SSL_library_init();
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	int sock = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server = {.sin_family = AF_INET,
	                             .sin_port = htons(PORT)};

	inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);

	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("connect");
		return 1;
	}

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);

	if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	char user[50], pass[50];
	printf("Username: ");
	scanf("%49s", user);
	printf("Password: ");
	scanf("%49s", pass);
	flush_stdin(); // important

	char auth[200];
	snprintf(auth, sizeof(auth), "AUTH %s %s\n", user, pass);
	SSL_write(ssl, auth, strlen(auth));

	char buffer[BUFFER_SIZE];
	int bytes = ssl_read_line(ssl, buffer, sizeof(buffer));
	if (bytes <= 0) {
		printf("Server disconnected during auth.\n");
		return 1;
	}

	if (strncmp(buffer, "OK", 2) != 0) {
		printf("Auth failed\n");
		return 0;
	}

	printf("Authenticated\n");

	while (1) {
		printf("cmd> ");
		if (!fgets(buffer, sizeof(buffer), stdin))
			break;

		if (strncmp(buffer, "exit", 4) == 0)
			break;

		char msg[BUFFER_SIZE];
		snprintf(msg, sizeof(msg), "CMD %s", buffer);
		SSL_write(ssl, msg, strlen(msg));

		// Read header: OUTPUT <len>\n
		char header[100];
		bytes = ssl_read_line(ssl, header, sizeof(header));
		if (bytes <= 0) {
			printf("Server disconnected.\n");
			break;
		}

		int out_len, exit_code;
		if (sscanf(header, "OUTPUT %d %d", &out_len, &exit_code) != 2) {
			printf("Protocol error. Received: %s\n", header);
			break;
		}

		if (out_len > 0) {
			char *output = malloc(out_len + 1);
			if (!output) {
				perror("malloc");
				break;
			}

			if (ssl_read_exact(ssl, output, out_len) <= 0) {
				printf("Failed reading command output.\n");
				free(output);
				break;
			}

			output[out_len] = '\0';
			printf("%s", output);
			free(output);
		} else {
			printf("(no output)");
		}

        printf("\n[exit code: %d]\n", exit_code);

		// Read trailing "\nEND\n"
		char endbuf[10];
		bytes = ssl_read_line(
		    ssl, endbuf,
		    sizeof(endbuf)); // consumes newline after output if needed

		if (bytes <= 0 || strcmp(endbuf, "END\n") != 0) {
			printf("\nProtocol error: expected END, got: %s\n", endbuf);
			break;
		}

		printf("\n");
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	SSL_CTX_free(ctx);
	return 0;
}
