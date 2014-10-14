# To compile ssl client and ssl server

CFLAGS  += -std=c99 -g3 -Wall
OFLAGS  += -O0
LDFLAGS += -L/usr/local/lib -lssl -lcrypto

APPS = src/ssl_server src/ssl_client

.SILENT:

all: $(APPS)

src/ssl_server: src/ssl_server.c
	echo "CC src/ssl_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) src/ssl_server.c $(LDFLAGS) -o $@

src/ssl_client: src/ssl_client.c
	echo "CC src/ssl_client.c"
	$(CC) $(CFLAGS) $(OFLAGS) src/ssl_client.c $(LDFLAGS) -o $@

clean:
	echo "Deleting -> rm -f $(APPS)"
	rm -f $(APPS)

list:
	echo $(APPS)
