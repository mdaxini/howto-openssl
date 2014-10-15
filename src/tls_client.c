/*
 * sslclient.c
 */

#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tlsutil.h"

#define CERTF "src/server.crt"
#define KEYF  "src/server.key"

int main() {
    const SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;
    X509* server_cert;
    int err;
    int sd;
    struct sockaddr_in sa;
    char* str;
    char buf[4096];


    /* ------------ */
    /* Init openssl */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ------------------------------------- */
    /* Using TLS 1.2 to prevent BEAST attack.*/
    meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);

    /* ---------------------------------------------------------------- */
    /* Cipher AES256-GCM-SHA384 - good performance with AES-NI support. */
    if (!SSL_CTX_set_cipher_list(ctx, "AES256-GCM-SHA384")) {
        printf("Could not set cipher list");
        exit(1);
    }

    /* ------------------------------- */
    /* Configure certificates and keys */
    if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
        printf("Could not disable compression");
        exit(2);
    }

    if (SSL_CTX_load_verify_locations(ctx, CERTF, 0) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(5);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        printf("Could not load cert file: ");
        ERR_print_errors_fp(stderr);
        exit(5);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        printf("Could not load key file");
        ERR_print_errors_fp(stderr);
        exit(6);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match public key in certificate.\n");
        exit(7);
    }

    /* Enable client certificate verification. Enable before accepting connections. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
    SSL_VERIFY_CLIENT_ONCE, 0);

    // To DELETE

    //CHK_SSL(err);

    /* --------------------------------------------- */
    /* Create a normal socket and connect to server. */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1"); /* Server IP */
    sa.sin_port = htons(1112); /* Server Port number */

    err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    CHK_ERR(err, "connect");

    printf("Connected to server %s, port %u\n", inet_ntoa(sa.sin_addr),
            ntohs(sa.sin_port));
    /* --------------- ---------------------------------- */
    /* Start SSL negotiation, connection available. */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl);
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl);
    CHK_SSL(err);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }

    /* -------------------------------------------------------- */
    /* Optional section of code, not required for data exchange */

    /* The cipher negotiated and being used */
    printf("Using cipher %s\n", SSL_get_cipher(ssl));

    /* Get server's certificate */
    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate:\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);

    /* Deallocate certificate, free memory */
    X509_free(server_cert);

    /* --------------------------------- */
    /* Data transfer - Send and Receive. */

    err = SSL_write(ssl, "PING", strlen("PING"));
    CHK_SSL(err);

    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(err);
    buf[err] = '\0';
    printf("Client Received %d chars - '%s'\n", err, buf);
    SSL_shutdown(ssl); /* send SSL/TLS close_notify */

    /* ----------------- */
    /* Release resources */

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
