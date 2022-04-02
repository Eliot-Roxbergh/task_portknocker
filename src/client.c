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

int start_client(void)
{
    int rv = EXIT_FAILURE;
    printf("Connecting to server %s:%d/UDP..\n", SERVER_IP, KEY_PORT);
    if (send_udp_secret() != 0) {
        fprintf(stdout, "INFO: UDP client, secret send, failed.\n");
        goto error;
    }

    // TODO implement
    printf("Connecting to server %s:%d/TCP..\n", SERVER_IP, TLS_PORT);
    if (start_tls_session() != 0) {
        fprintf(stderr, "ERROR: Client TLS failed\n");
        goto error;
    }

    rv = EXIT_SUCCESS;
    fprintf(stdout, "INFO: OK! Client happy\n");
error:
    return rv;
}

int send_udp_secret(void)
{
    int rv = -1;
    int fd;
    struct sockaddr_in server_addr;
    socklen_t server_addrlen;
    size_t buf_len = 256;
    ssize_t msg_len;
    char buf[buf_len];

    errno = 0;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Could not get socket file descriptor: ");
        rv = -1;
        goto error;
    }

    // codechecker_false_positive [security.insecureAPI.DeprecatedOrUnsafeBufferHandling] suppress : safe memset usage
    memset(&server_addr, 0, sizeof server_addr);
    server_addrlen = sizeof server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(KEY_PORT);

    const char *secret = secret_key_str();
    sendto(fd, secret, strlen(secret), MSG_CONFIRM, (const struct sockaddr *)&server_addr, server_addrlen);

    fprintf(stdout, "INFO: Secret sent, awaiting acknowledgement\n");
    errno = 0;
    if ((msg_len = recvfrom(fd, buf, buf_len, MSG_WAITALL, (struct sockaddr * restrict) & server_addr,
                            &server_addrlen)) < 0) {
        perror("Could not recieve: ");
        rv = -1;
        goto error;
    }
    buf[msg_len] = '\0';

    if (strcmp(buf, ACK_MSG) == 0) {
        fprintf(stdout, "INFO: Secret accepted by server\n");
    } else {
        rv = -1;
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
