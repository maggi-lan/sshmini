# sshmini — Makefile
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -pthread
LDFLAGS = -lssl -lcrypto -lpthread

COMMON_SRC = common/utils.c
COMMON_OBJ = $(COMMON_SRC:.c=.o)

SERVER_SRC = server/server.c server/auth.c $(COMMON_SRC)
CLIENT_SRC = client/client.c $(COMMON_SRC)
BENCH_SRC  = client/bench.c  $(COMMON_SRC)
ADDUSER_SRC= server/adduser.c server/auth.c $(COMMON_SRC)

.PHONY: all clean certs

all: sshmini-server sshmini-client sshmini-bench sshmini-adduser

sshmini-server: $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sshmini-client: $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sshmini-bench: $(BENCH_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sshmini-adduser: $(ADDUSER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generate self-signed certificate for the server
certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
	  -out certs/server.crt -days 365 -nodes \
	  -subj "/CN=sshmini-server/O=Lab/C=IN"
	@echo "Certificates generated in ./certs/"

clean:
	rm -f sshmini-server sshmini-client sshmini-bench sshmini-adduser
	rm -f common/*.o server/*.o client/*.o
	rm -f audit.log
