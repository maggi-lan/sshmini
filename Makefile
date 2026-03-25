CC=gcc
CFLAGS=-Wall -pthread
LIBS=-lssl -lcrypto

all:
	$(CC) server.c -o server $(CFLAGS) $(LIBS)
	$(CC) client.c -o client $(CFLAGS) $(LIBS)
