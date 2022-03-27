#include "server.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include "config.h"

// TODO implement
int listen_udp_secret() { return 0; }
int listen_tls_session() { return 0; }

// server
int main(void)
{
    int rv = EXIT_FAILURE;
    fprintf(stdout, "Server is listening for package on 53/udp");
    while (listen_udp_secret() != 0)
        ;

    // TLS port open for remainder of execution
    fprintf(stdout, "Server is open for TLS on 443/tcp");
    while (1) {
        errno = 0;
        listen_tls_session();
        if (errno != 0) {
            perror("Failed: ");
            goto error;
        }
    }

    rv = EXIT_SUCCESS;
error:
    return rv;
}
