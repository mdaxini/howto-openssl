/*
 * sslserver.c
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>
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
    X509* client_cert;
    int err;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_s;  //server
    struct sockaddr_in sa_c;  //client
    socklen_t client_len;
    char* str;
    char buf[4096];


    /* ------------ */
    /* Init openssl */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ------------------------------------- */
    /* Using TLS 1.2 to prevent BEAST attack.*/
    meth = TLSv1_2_server_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    /* ---------------------------------------------------------------- */
    /* Cipher AES128-GCM-SHA256 or AES256-GCM-SHA384 */
    //if (!SSL_CTX_set_cipher_list(ctx, "AES256-GCM-SHA384")) {
    if (!SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256")) {
        printf("Could not set cipher.");
        exit(3);
    }

    /* ---------------------------------------------------------------- */
    /* Disable compression to prevent BREACH and CRIME vulnerabilities. */
    if (!SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) {
        printf("Could not disable compression.");
        exit(4);
    }

    /* ------------------------------- */
    /* Configure certificates and keys */
    if (SSL_CTX_load_verify_locations(ctx, CERTF, 0) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(5);
    }

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(5);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
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

    /* --------------------------------------------------- */
    /* Create normal TCP socket for receiving connections. */

    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    memset(&sa_s, '\0', sizeof(sa_s));
    sa_s.sin_family = AF_INET;
    sa_s.sin_addr.s_addr = INADDR_ANY;
    sa_s.sin_port = htons(1112); /* Server Port number */

    err = bind(listen_sd, (struct sockaddr*) &sa_s, sizeof(sa_s));
    CHK_ERR(err, "bind");

    /* Receive a TCP connection. */

    err = listen(listen_sd, 5);
    CHK_ERR(err, "listen");

    client_len = sizeof(sa_c);
    sd = accept(listen_sd, (struct sockaddr*) &sa_c, &client_len);
    CHK_ERR(sd, "accept");
    close(listen_sd);

    printf("Client connected from %s, port %u\n", inet_ntoa(sa_c.sin_addr),
            ntohs(sa_c.sin_port));

    /* ------------------------------------- */
    /* Server side SSL, connection is ready. */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl);

    SSL_set_fd(ssl, sd);
    SSL_set_accept_state(ssl);
    err = SSL_accept(ssl);
    CHK_SSL(err);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(8);
    }

    /* -------------------------------------------------------- */
    /* Optional section of code, not required for data exchange */

    printf("Server Version: %s\n", SSL_get_version(ssl));

    /* The cipher negotiated and being used */
    printf("Using cipher %s\n", SSL_get_cipher(ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        printf("Client certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t Subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t Issuer: %s\n", str);
        OPENSSL_free(str);

        /* Deallocate certificate, free memory */
        X509_free(client_cert);
    } else {
        printf("Client does not have certificate.\n");
    }

    /* --------------------------------- */
    /* Data transfer - Receive and Send. */

    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(err);
    buf[err] = '\0';
    printf("Server received %d chars - '%s'\n", err, buf);

    err = SSL_write(ssl, "PONG", strlen("PONG"));
    CHK_SSL(err);

    /* ----------------- */
    /* Release resources */

    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}


