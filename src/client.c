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

int start_client(const char *secret)
{
    int rv = -1;

    fprintf(stdout, "INFO: Knocking on server (%s:%u/UDP) ...\n", SERVER_IP, KEY_PORT);
    if (send_udp_secret(secret) != 0) {
        fprintf(stderr, "INFO: UDP client, secret send, failed.\n");
        goto error;
    }

    // TODO implement
    printf("Connecting to server %s:%d/TCP..\n", SERVER_IP, TLS_PORT);
    if (start_tls_session() != 0) {
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

    errno = 0;
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

/* Helper functions */

static int udp_client_send_secret(int fd, const char *secret)
{
    int rv = -1;
    struct sockaddr_in server_addr;
    socklen_t server_addrlen;
    size_t buf_len = BUF_LEN;
    ssize_t msg_len;
    char buf[buf_len];

    // codechecker_false_positive [security.insecureAPI.DeprecatedOrUnsafeBufferHandling] suppress : safe memset usage
    memset(&server_addr, 0, sizeof server_addr);
    server_addrlen = sizeof server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(KEY_PORT);

    sendto(fd, secret, strlen(secret), MSG_CONFIRM, (const struct sockaddr *)&server_addr, server_addrlen);

    fprintf(stdout, "INFO: Secret sent, awaiting acknowledgement\n");
    errno = 0;
    if ((msg_len = recvfrom(fd, buf, buf_len, MSG_WAITALL, (struct sockaddr * restrict) & server_addr,
                            &server_addrlen)) < 0) {
        perror("ERROR: Could not recieve: ");
        goto error;
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

int start_tls_session(void)
{
    // TODO implement
    return 0;
}
