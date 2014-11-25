#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

#include "tlsutil.h"

#define CERTF "src/server.crt"
#define KEYF  "src/server.key"

#define MAXEVENTS 128

void init_ssl_opts(SSL_CTX* ctx) {
    /* ---------------------------------------------------------------- */
    /* Cipher AES128-GCM-SHA256 and AES256-GCM-SHA384 - good performance with AES-NI support. */
    if (!SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256")) {
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
        fprintf(stderr,
                "Private key does not match public key in certificate.\n");
        exit(7);
    }
    /* Enable client certificate verification. Enable before accepting connections. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
    SSL_VERIFY_CLIENT_ONCE, 0);
}

static void
dump_cert_info(SSL *ssl, bool server) {

    if(server) {
        printf("Ssl server version: %s", SSL_get_version(ssl));
    }
    else {
        printf("Client Version: %s", SSL_get_version(ssl));
    }

    /* The cipher negotiated and being used */
    printf("Using cipher %s", SSL_get_cipher(ssl));

    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    X509 *client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        if(server) {
        printf("Client certificate:\n");
        }
        else {
            printf("Server certificate:\n");
        }
        char *str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        if(str == NULL) {
            printf("warn X509 subject name is null");
        }
        printf("\t Subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        if(str == NULL) {
            printf("warn X509 issuer name is null");
        }
        printf("\t Issuer: %s\n", str);
        OPENSSL_free(str);

        /* Deallocate certificate, free memory */
        X509_free(client_cert);
    } else {
        printf("Client does not have certificate.\n");
    }
}

int main(int argc, char *argv[]) {

    // SSL send
    // make socket non-blocking

    const SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL* ssl;
    //X509* server_cert;
    int err;
    int sd;
    struct sockaddr_in sa;
    //char* str;
    char buf[4096];

    printf("epoll openssl tls client..");

    /* ------------ */
    /* Init openssl */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    /* ------------------------------------- */
    meth = TLSv1_2_client_method();
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);

    init_ssl_opts(ctx);
    /* --------------------------------------------- */
    /* Create a normal socket and connect to server. */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    // non-blocking client socket
    int flags = fcntl(sd, F_GETFL, 0);
    if (flags < 0) {
      exit(12);
    }
    fcntl(sd, F_SETFL, flags | O_NONBLOCK);

    // ---------------------

    memset(&sa, '\0', sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1"); /* Server IP */
    sa.sin_port = htons(1112); /* Server Port number */

    printf("Connected to server %s, port %u\n", inet_ntoa(sa.sin_addr),
            ntohs(sa.sin_port));

    err = connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    if (err < 0 && errno != EINPROGRESS) {
        perror("connect != EINPROGRESS");
        exit (15);
    }

    // ----------- Epoll Create ---------------------- //
    int efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create");
        exit(1);
    }

    struct epoll_event event;
    event.data.fd = sd;
    event.events = EPOLLIN | EPOLLOUT | EPOLLET |EPOLLERR | EPOLLHUP;

    int s = epoll_ctl(efd, EPOLL_CTL_ADD, sd, &event);
    if (s == -1) {
        perror("epoll_ctl");
        exit(2);
    }

    // ------------------------------- //

    /* --------------- ---------------------------------- */
    /* Start SSL negotiation, connection available. */
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);

    SSL_set_fd(ssl, sd);
    SSL_set_connect_state(ssl);

    for(;;) {
        int success = SSL_connect(ssl);

        if(success < 0) {
            err = SSL_get_error(ssl, success);

            /* Non-blocking operation did not complete. Try again later. */
            if (err == SSL_ERROR_WANT_READ ||
                    err == SSL_ERROR_WANT_WRITE ||
                    err == SSL_ERROR_WANT_X509_LOOKUP) {
                continue;
            }
            else if(err == SSL_ERROR_ZERO_RETURN) {
                printf("SSL_connect: close notify received from peer");
                exit(18);
            }
            else {
                printf("Error SSL_connect: %d", err);
                perror("perror: ");
                SSL_free(ssl);
                close(sd);
                close(efd);
                exit(16);
            }
        }
        else {
            dump_cert_info(ssl, false);
            break;
        }
    }

    /* Buffer where events are returned */
    struct epoll_event* events = calloc(MAXEVENTS, sizeof event);
    /* The event loop */
    while (1) {
        int n = epoll_wait(efd, events, MAXEVENTS, -1);
        if (n < 0 && n == EINTR) {
            printf("epoll_wait System call interrupted. Continue..");
            continue;
        }

        int i;
        for (i = 0; i < n; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)
                    || (!(events[i].events & (EPOLLIN | EPOLLOUT)))) {
                /* An error has occurred on this socket or the socket is not
                 ready for reading (why were we notified then?) */
                fprintf(stderr, "epoll error\n");
                close(events[i].data.fd);
                continue;
            }
            // read
            else if (events->events & (EPOLLIN | EPOLLHUP)) {
                err = SSL_read(ssl, buf, sizeof(buf) - 1);
                CHK_SSL(err);
                buf[err] = '\0';
                printf("Client Received %d chars - '%s'\n", err, buf);

                if (err <= 0) {
                    if(err == SSL_ERROR_WANT_READ ||
                        err == SSL_ERROR_WANT_WRITE ||
                        err == SSL_ERROR_WANT_X509_LOOKUP) {
                        printf("Read could not complete. Will be invoked later.");
                        break;
                    }
                    else if(err == SSL_ERROR_ZERO_RETURN) {
                        printf("SSL_read: close notify received from peer");
                        return 0;
                    }
                    else {
                        printf("Error during SSL_read");
                        exit(17);
                    }
                }
                exit(0);
            }
            //write
            else if (events->events & EPOLLOUT) {
                err = SSL_write(ssl, "PING", strlen("PING"));
                CHK_SSL(err);

                if (err <= 0) {
                    if(err == SSL_ERROR_WANT_READ ||
                        err == SSL_ERROR_WANT_WRITE ||
                        err == SSL_ERROR_WANT_X509_LOOKUP) {
                        printf("Write could not complete. Will be invoked later.");
                        break;
                    }
                    else if(err == SSL_ERROR_ZERO_RETURN) {
                        printf("SSL_write: close notify received from peer");
                        return 0;
                    }
                    else {
                        printf("Error during SSL_write");
                        exit(17);
                    }
                }
            }
        }
    }
    free(events);
    close(sd);
    close(efd);
    return 0;
}
