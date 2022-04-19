#include "client.h"
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "helper.h"
#include "portknock.h"

/*
 * Main function called from tool
 */
int start_client(const char *secret)
{
    int rv = -1;

    fprintf(stdout, "INFO: Knocking on server (%s:%u/UDP) ...\n", SERVER_IP, KEY_PORT);
    if (send_udp_secret(secret) != 0) {
        fprintf(stderr, "INFO: UDP client, secret send, failed.\n");
        goto error;
    }

    fprintf(stdout, "INFO: Connecting to server with TLS (%s:%u/TCP) ...\n", SERVER_IP, TLS_PORT);
    if ((rv = start_tls_session() != 0)) {
        fprintf(stderr, "ERROR: Client TLS failed\n");
        goto error;
    }

    fprintf(stdout, "INFO: OK! Client happy\n");
    rv = 0;
error:
    return rv;
}

/*
 * Send secret to server over UDP
 */
static int udp_client_send_secret(int, const char *);

int send_udp_secret(const char *secret)
{
    int rv = -1;
    int fd;

    // check secret, use hardcoded if NULL
    secret = get_secret_str(secret);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("ERROR: Could not get socket file descriptor: ");
        goto error;
    }

    if (udp_client_send_secret(fd, secret) != 0) {
        goto error;
    }

    rv = 0;
error:
    return rv;
}

/*
 * Connect to server over TLS,
 * and then send and receive a message over the secure channel
 */
static int tls_client_setup_openssl(SSL_CTX **);
static int tls_client_tcp_connect(int *);
static int tls_client_start_session(SSL_CTX *, int);

int start_tls_session(void)
{
    int rv = -1;
    int fd = -1;
    SSL_CTX *ctx = NULL;

    if (tls_client_setup_openssl(&ctx) != 0) {
        goto error;
    }
    if (tls_client_tcp_connect(&fd) != 0) {
        goto error;
    }
    if (tls_client_start_session(ctx, fd) != 0) {
        goto error;
    }

    rv = 0;
error:
    if (fd >= 0) {
        close(fd);
    }
    if (rv != 0) {
        ERR_print_errors_fp(stderr);
    }
    SSL_CTX_free(ctx);
    return rv;
}

/* Helper functions */

static int udp_client_send_secret(int fd, const char *secret)
{
    int rv = -1;
    struct sockaddr_in server_addr;
    socklen_t server_addrlen;
    size_t buf_len = BUF_LEN;
    ssize_t msg_len;
    char buf[buf_len];

    server_addrlen = sizeof server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(KEY_PORT);

    sendto(fd, secret, strlen(secret), MSG_CONFIRM, (const struct sockaddr *)&server_addr, server_addrlen);

    fprintf(stdout, "INFO: Secret sent, awaiting acknowledgement\n");
    if ((msg_len = recvfrom(fd, buf, buf_len - 1, MSG_WAITALL, (struct sockaddr * restrict) & server_addr,
                            &server_addrlen)) < 0) {
        perror("ERROR: Could not recieve: ");
        goto error;
    }
    // To make codechecker happy, but recvfrom should not return more than given buf_len (?)
    if ((size_t)msg_len >= buf_len) {
        msg_len = (ssize_t)buf_len - 1;
    }
    buf[msg_len] = '\0';

    if (strcmp(buf, ACK_MSG) == 0) {
        fprintf(stdout, "INFO: Secret accepted by server\n");
    } else {
        goto error;
    }

    rv = 0;
error:
    return rv;
}

static int tls_client_setup_openssl(SSL_CTX **ctx_p)
{
    /* OpenSSL config */
    int rv = -1;
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "ERROR: Unable to create SSL context\n");
        goto error;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, CLIENT_TLS_CHAIN) != 1) {
        goto error;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_TLS_KEY, SSL_FILETYPE_PEM) != 1) {
        goto error;
    }

    // Set trusted CAs
    if (SSL_CTX_load_verify_locations(ctx, SERVER_CA_CERT, NULL) != 1) {
        goto error;
    }

    /* Optional hardening */
    // Require TLS 1.3
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        fprintf(stderr, "ERROR: Could not set version, TLS 1.3\n");
        goto error;
    }

    rv = 0;
error:
    *ctx_p = ctx;
    return rv;
}

static int tls_client_tcp_connect(int *fd_p)
{
    /* Establish TCP session */
    int rv = -1;
    int fd;
    struct sockaddr_in server_addr;
    socklen_t server_addrlen;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("ERROR: Could not get socket file descriptor: ");
        goto error;
    }

    usleep(20000); /* ugly hack, in case client is too fast TODO */

    server_addrlen = sizeof server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(TLS_PORT);

    if (connect(fd, (struct sockaddr *)&server_addr, server_addrlen) != 0) {
        perror("ERROR: Unable to connect");
        goto error;
    }

    rv = 0;
error:
    *fd_p = fd;
    return rv;
}

static int tls_client_start_session(SSL_CTX *ctx, int fd)
{
    /* Start TLS session (using already established TCP connection) */
    int rv = -1;
    SSL *ssl = NULL;

    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: SSL_new ctx fail");
        goto error;
    }
    if (SSL_set_fd(ssl, fd) != 1) {
        fprintf(stderr, "ERROR: SSL_set_fd fail");
        goto error;
    }
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "ERROR: Failed to connect to server\n");
        goto error;
    }

    /* Connection established, we are done... could do anything here
     * For now, do simple message exchange to show secure communication works */
    {
        int buf_len = BUF_LEN;
        char buf[buf_len];
        int bytes;
        bytes = SSL_read(ssl, buf, buf_len);
        if (bytes > 0 && bytes < buf_len) {
            buf[bytes] = '\0';
            fprintf(stdout, "MSG: Server says \"%s\"\n", buf);
        } else {
            fprintf(stderr, "ERROR: SSL_read failed\n");
            goto error;
        }
        const char *msg = "Hello!";
        SSL_write(ssl, msg, (int)strlen(msg));
    }

    rv = 0;
error:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    return rv;
}
