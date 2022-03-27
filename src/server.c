#include "server.h"
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

/* [IMPROVEMENT suggestion]
 * In case a message is lost or other error, we can end up in a stuck state.
 * TODO: use multiple threads or set timeout with poll() or similar
 *
 * [IMPROVEMENT suggestion]
 * It's slightly inefficient to send the secret as regular (utf-8) chars, instead of raw data.
 *
 * [IMPROVEMENT suggestion]
 * Send some kind of none / signature / derived secret, instead of secret key directly
 *
 */

// server
int main(void)
{
    int rv = EXIT_FAILURE;

    fprintf(stdout, "INFO: Server is listening for package on %u/udp\n", KEY_PORT);
    if (listen_udp_secret() != 0) {
        fprintf(stdout, "ERROR: UDP server, secret recieved, failed\n");
        goto error;
    }

    // TODO implement
    fprintf(stdout, "INFO: Server is open for TLS on 443/tcp\n");
    while (listen_tls_session() != 0) {
        fprintf(stderr, "ERROR: TLS failed. Retrying..\n");
        sleep(1);
    }

    fprintf(stdout, "INFO: Server is done, OK!\n");

error:
    rv = EXIT_SUCCESS;
    return rv;
}

int listen_udp_secret(void)
{
    int rv = -1;
    int fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t server_addrlen, client_addrlen;
    size_t buf_len = strlen(secret_key_str()) + 1;
    ssize_t msg_len;
    char buf[buf_len];

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("ERROR: Could not get socket file descriptor: ");
        rv = -1;
        goto error;
    }

    // codechecker_false_positive [security.insecureAPI.DeprecatedOrUnsafeBufferHandling] suppress : safe memset usage
    memset(&client_addr, 0, sizeof client_addr);
    client_addrlen = sizeof client_addr;

    // codechecker_false_positive [security.insecureAPI.DeprecatedOrUnsafeBufferHandling] suppress : safe memset usage
    memset(&server_addr, 0, sizeof server_addr);
    server_addrlen = sizeof server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; /* bind to all interfaces */
    server_addr.sin_port = htons(KEY_PORT);

    errno = 0;
    if (bind(fd, (const struct sockaddr *)&server_addr, server_addrlen) != 0) {
        perror("ERROR: Could not bind: ");
        rv = -1;
        goto error;
    }

    errno = 0;
    if ((msg_len = recvfrom(fd, buf, buf_len, MSG_WAITALL, (struct sockaddr * restrict) & client_addr,
                            &client_addrlen)) < 0) {
        perror("ERROR: Could not recieve: ");
        rv = -1;
        goto error;
    }
    buf[msg_len] = '\0';

    const char *reply;
    if (strcmp(buf, secret_key_str()) == 0) {
        fprintf(stdout, "INFO: Client accepted\n");
        reply = ACK_MSG;
        sendto(fd, reply, strlen(reply), MSG_CONFIRM, (const struct sockaddr *)&client_addr, client_addrlen);
    } else {
        fprintf(stdout, "INFO: Client bad secret\n");
        reply = "Wrong secret, try again!";
        sendto(fd, reply, strlen(reply), MSG_CONFIRM, (const struct sockaddr *)&client_addr, client_addrlen);
        rv = -1;
        goto error;
    }

    rv = 0;
error:
    return rv;
}

static int listen_tls_session(void)
{
    // TODO implement
    return 0;
}
