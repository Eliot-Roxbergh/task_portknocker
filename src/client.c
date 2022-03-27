#include "client.h"
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include "config.h"

// TODO implement
int send_udp_secret() { return 0; }
int start_tls_session() { return 0; }

// client
int main(void)
{
    int rv = EXIT_FAILURE;
    if (send_udp_secret() != 0) {
        fprintf(stderr, "Client UDP failed");
        return rv;
    }
    if (start_tls_session() != 0) {
        fprintf(stderr, "Client TLS failed");
        return rv;
    }

    rv = EXIT_SUCCESS;
    fprintf(stdout, "OK! Client happy");
    return rv;
}
