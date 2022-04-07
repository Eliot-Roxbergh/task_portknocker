#include "server.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "helper.h"
#include "portknock.h"

static whitelist client_whitelist;

/*
 * Some [improvement] suggestions:
 *
 * - In case a message is lost or other error, we can end up in a stuck state!
 *       This applies for both client and server parts.
 *       Suggestion, use multiple threads or set timeout with poll() or similar
 *
 * - Send some kind of nonce / signature / derived secret, instead of secret key directly
 *  Such as to encrypt the current time/day, or client public IP address, derive secret from server nonce etc. etc.
 *
 * - Take server IP and ports as arguments
 *
 * - It is slightly inefficient to send the secret as regular (utf-8) chars, instead of raw data.
 *
 * - Make sure client and server certs are verified properly. e.g. it's possible to add hostname verification
 *
 */

/*
 * Main function called from tool
 */
int start_server(const char *secret)
{
    int rv = -1;

    fprintf(stdout, "INFO: Server listening for knock on %u/udp ...\n", KEY_PORT);
    if (listen_udp_secret(secret) != 0) {
        fprintf(stderr, "ERROR: UDP server, secret recieved, failed\n");
        goto error;
    }

    fprintf(stdout, "INFO: Server open for TLS on %u/tcp ...\n", TLS_PORT);
    if ((rv = listen_tls_session()) != 0) {
        fprintf(stderr, "ERROR: TLS failed!\n");
        goto error;
    }

    fprintf(stdout, "INFO: Server is done, OK!\n");
    rv = 0;
error:
    if (client_whitelist.addr) {
        free(client_whitelist.addr);
        client_whitelist.addr = NULL;
        client_whitelist.elems = 0;
    }
    return rv;
}

/*
 * Receive a message and send ack on UDP socket,
 * if received message is correct secret -> return 0  (success)
 */
static int udp_server_open_socket(int *);
static int udp_server_receive_secret(int, const char *);

int listen_udp_secret(const char *secret)
{
    int rv = -1;
    int fd = -1;

    /* Setup socket */
    if (udp_server_open_socket(&fd) != 0) {
        goto error;
    }

    /* Receive secret and ack if correct */
    if (udp_server_receive_secret(fd, secret) != 0) {
        goto error;
    }

    rv = 0;
error:
    if (fd >= 0) {
        close(fd);
    }
    return rv;
}

/*
 * Start a TLS server and send a simple handshake once a secure session has been established.
 *  As soon as secure communication with client is successful, exit with success (proof of concept complete).
 */
static int tls_server_setup_openssl(SSL_CTX **);
static int tls_server_tcp_listen(int *);
static int tls_server_start_session(SSL_CTX *, int);

int listen_tls_session(void)
{
    int rv = -1;
    int fd = -1;
    SSL_CTX *ctx = NULL;

    if (tls_server_setup_openssl(&ctx) != 0) {
        ERR_print_errors_fp(stderr);
        goto error;
    }

    if (tls_server_tcp_listen(&fd) != 0) {
        goto error;
    }

    if (tls_server_start_session(ctx, fd) != 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "ERROR: TLS failed\n");
        goto error;
    }

    rv = 0;
error:
    if (fd >= 0) {
        close(fd);
    }
    SSL_CTX_free(ctx);
    return rv;
}

/*
 * Maintain whitelist of approved IP addresses
 * A client is whitelisted for TLS by performing portknock
 */

bool client_in_whitelist(unsigned long addr)
{
    if (!client_whitelist.addr) {
        fprintf(stderr, "ERROR: Read from client whitelist, whitelist is empty!\n");
        return false;
    }
    for (size_t i = 0; i < client_whitelist.elems; i++) {
        if (client_whitelist.addr[i] == addr) {
            fprintf(stdout, "INFO: Client is in whitelist, proceed.\n");
            return true;
        }
    }
    return false;
}

int add_client_to_whitelist(unsigned long addr)
{
    if (client_whitelist.elems == SIZE_MAX) {
        fprintf(stderr, "ERROR: Sorry, client whitelist is full (reached %zu entries)\n", client_whitelist.elems);
        return 1;
    }

    size_t elems = ++(client_whitelist.elems);
    size_t new_size = elems * sizeof(*client_whitelist.addr);
    client_whitelist.addr = realloc(client_whitelist.addr, new_size);
    client_whitelist.addr[elems - 1] = addr;

    /* TODO this below (print IP address) was done in haste, and only supports ipv4.
     * Consider e.g. using inet_ntop or store as string instead with getnameinfo().
     */
    struct in_addr tmp;
    tmp.s_addr = (unsigned)addr;
    fprintf(stdout, "INFO: Adding client \"%s\" to whitelist.\n", inet_ntoa(tmp));

    return 0;
}

/* Helper functions */

static int udp_server_open_socket(int *fd_p)
{
    int rv = -1;
    int fd;
    struct sockaddr_in server_addr;
    socklen_t server_addrlen;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("ERROR: Could not get socket file descriptor: ");
        goto error;
    }

    server_addrlen = sizeof server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; /* bind to all interfaces */
    server_addr.sin_port = htons(KEY_PORT);
    if (bind(fd, (const struct sockaddr *)&server_addr, server_addrlen) != 0) {
        perror("ERROR: Could not bind: ");
        goto error;
    }

    rv = 0;
error:
    *fd_p = fd;
    return rv;
}

static int udp_server_receive_secret(int fd, const char *secret)
{
    int rv = -1;
    ssize_t msg_len;

    // check secret, use hardcoded if NULL
    secret = get_secret_str(secret);
    size_t buf_len = strlen(secret) + 1;
    char buf[buf_len];

    struct sockaddr_in client_addr;
    socklen_t client_addrlen;

    // codechecker_false_positive [security.insecureAPI.DeprecatedOrUnsafeBufferHandling] suppress : safe memset usage
    memset(&client_addr, 0, sizeof client_addr);
    client_addrlen = sizeof client_addr;

    if ((msg_len = recvfrom(fd, buf, buf_len - 1, MSG_WAITALL, (struct sockaddr * restrict) & client_addr,
                            &client_addrlen)) < 0) {
        perror("ERROR: Could not recieve: ");
        goto error;
    }
    // To make codechecker happy, but recvfrom should not return more than given buf_len (?)
    if ((size_t)msg_len >= buf_len) {
        msg_len = (ssize_t)buf_len - 1;
    }
    buf[msg_len] = '\0';

    const char *reply;
    if (strcmp(buf, secret) == 0) {
        fprintf(stdout, "INFO: Client accepted\n");
        reply = ACK_MSG;
        (void)sendto(fd, reply, strlen(reply), MSG_CONFIRM, (const struct sockaddr *)&client_addr, client_addrlen);
    } else {
        fprintf(stdout, "INFO: Client bad secret\n");
        reply = BAD_MSG;
        (void)sendto(fd, reply, strlen(reply), MSG_CONFIRM, (const struct sockaddr *)&client_addr, client_addrlen);
        goto error;
    }

    // Add client to whitelist
    if (!getpeername(fd, (struct sockaddr *)&client_addr, &client_addrlen)) {  // not necessary?
        perror("ERROR: Get client IP failed");
        goto error;
    }
    if (add_client_to_whitelist(client_addr.sin_addr.s_addr) != 0) {
        fprintf(stderr, "ERROR: Client verified OK, but could not add to whitelist\n");
        goto error;
    }
    rv = 0;
error:
    return rv;
}

static int tls_server_setup_openssl(SSL_CTX **ctx_p)
{
    /* OpenSSL config */
    SSL_CTX *ctx;
    const SSL_METHOD *method;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "ERROR: Unable to create SSL context\n");
        goto error;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, SERVER_TLS_CHAIN) != 1) {
        goto error;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_TLS_KEY, SSL_FILETYPE_PEM) != 1) {
        goto error;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "ERROR: Private key mismatch/error\n");
        goto error;
    }

    /* Optional hardening */

    // Require TLS 1.3
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        fprintf(stderr, "ERROR: Could not set version, TLS 1.3\n");
        goto error;
    }

    // Enable mutual authentication (i.e. check client cert)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // Set trusted CAs for mutual authentication
    if (SSL_CTX_load_verify_locations(ctx, CLIENT_CA_CERT, NULL) != 1) {
        goto error;
    }

    *ctx_p = ctx;
    return 0;
error:
    return 1;
}

static int tls_server_tcp_listen(int *fd_p)
{
    /* Setup TCP socket */
    int rv = -1;
    int fd;
    struct sockaddr_in server_addr;
    socklen_t server_addrlen;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("ERROR: Could not get socket file descriptor: ");
        goto error;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; /* bind to all interfaces */
    server_addr.sin_port = htons(TLS_PORT);
    server_addrlen = sizeof server_addr;

    if (bind(fd, (const struct sockaddr *)&server_addr, server_addrlen) != 0) {
        perror("ERROR: Could not bind: ");
        goto error;
    }

    if (listen(fd, 1) < 0) {
        perror("ERROR: Unable to listen");
        goto error;
    }

    rv = 0;
error:
    *fd_p = fd;
    return rv;
}

static int tls_server_start_session(SSL_CTX *ctx, int socket_fd)
{
    /* accept TCP connection and establish TLS session */
    int rv = -1;
    struct sockaddr_in client_addr;
    unsigned int client_addrlen = sizeof client_addr;
    SSL *ssl = NULL;
    int client_fd = -1;

    client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &client_addrlen);
    if (client_fd < 0) {
        perror("ERROR: Socket could not accept");
        goto error;
    }

    /* Ensure client is whitelisted */
    if (!getpeername(socket_fd, (struct sockaddr *)&client_addr, &client_addrlen)) {  // not necessary?
        perror("ERROR: Get client IP failed");
        goto error;
    }
    if (!client_in_whitelist(client_addr.sin_addr.s_addr)) {
        fprintf(stderr, "ERROR: client IP not in whitelist\n");
        goto error;
    }

    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: SSL_new ctx fail");
        goto error;
    }
    if (SSL_set_fd(ssl, client_fd) != 1) {
        fprintf(stderr, "ERROR: SSL_set_fd fail");
        goto error;
    }

    if (SSL_accept(ssl) != 1) {
        fprintf(stderr, "ERROR: SSL accept fail");
        goto error;
    } else {
        fprintf(stdout, "INFO: Connection successful!\n");
    }

    /* Connection established, we are done... could do anything here
     * For now, do simple message exchange to show secure communication works */
    {
        int bytes;
        const char *reply = ACK_MSG;
        int buf_len = BUF_LEN;
        char buf[buf_len];
        assert(strlen(reply) <= INT_MAX);

        SSL_write(ssl, reply, (int)strlen(reply));
        bytes = SSL_read(ssl, buf, buf_len);
        if (bytes > 0 && bytes < buf_len) {
            buf[bytes] = '\0';
            fprintf(stdout, "MSG: Client says \"%s\"\n", buf);
        } else {
            fprintf(stderr, "ERROR: SSL_read failed\n");
            goto error;
        }
    }

    rv = 0;
error:
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (client_fd >= 0) {
        close(client_fd);
    }
    return rv;
}
