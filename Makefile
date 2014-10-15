# To compile tls client and tls server

CFLAGS  += -std=c99 -g3 -Wall
OFLAGS  += -O0
LDFLAGS += -L/usr/local/lib -lssl -lcrypto

APPS = src/tls_server src/tls_client

.SILENT:

all: $(APPS)

src/tls_server: src/tls_server.c
	echo "CC src/tls_server.c"
	$(CC) $(CFLAGS) $(OFLAGS) src/tls_server.c $(LDFLAGS) -o $@

src/tls_client: src/tls_client.c
	echo "CC src/tls_client.c"
	$(CC) $(CFLAGS) $(OFLAGS) src/tls_client.c $(LDFLAGS) -o $@

clean:
	echo "Deleting -> rm -f $(APPS)"
	rm -f $(APPS)

list:
	echo $(APPS)
