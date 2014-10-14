howto-openssl
=============

This is an example of creating a server and a client that communicate over TLS 1.2 with cipher TLS_RSA_WITH_AES_256_GCM_SHA384 (AES256-GCM-SHA384). It also demonstrates how to perform server side and client side certificate authentication and verification. In this example the certificate and the private key are shared by the server and the client. However, you can easily use a different certificate and key. The instructions for creating these are outlined below.

A detailed treatise on the technical choices made for this example, and more details about OpenSSL and some of its tooling can be found in the post in the wiki for this project.

===

## Running the server and client

To compile, run from the directory with the Makefile:

	make

To clean artifacts from compile, run from the directory with the Makefile:

	make clean

Run the server (accepts connection on localhost:1112):

	src/ssl_server

Run the client (connects to server on localhost:1112:

	src/ssl_client

The server and the client use the server.crt and server.key from the src folder.

===
## Testing the server and client independently
### Testing the server
	src/ssl_server

	openssl s_client -msg -verify -tls1_2  -state -showcerts -cert src/server.crt -key src/server.key -connect localhost:1112

	Enter any text and hit enter, the server displays the client message and sends back "PONG".

The s_client command connects to the TLS 1.2 speaking server on localhost and port 1112 using the certificate server.crt and key server.key. It also validates the server certificate. It will display the handshake and certificate informaiton in detail.

### Testing the client
	openssl s_server -msg -verify -tls1_2 -state -cert src/server.crt -key src/server.key -accept 1112

	src/ssl_client

The client sends a PING to the server, and the server displays it.

===

