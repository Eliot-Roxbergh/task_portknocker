#include "portknock.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* [IMPROVEMENT suggestion]
 * Take more inputs, such as server IP (for client) and ports to use.
 * Another additional feature would be to have timeout, retry, etc.
 */

void usage(FILE *stream, const char *prog)
{
    fprintf(stream, "Usage: %s [help] [server]\n", prog);
    fprintf(stream, "With no args, client is started with default config\n\n");
}

int main(int argc, char **argv)
{
    int rv = -1;
    bool isServer = false;

    // optional parameters
    if (argc >= 2) {
        if (strcmp(argv[1], "server") == 0) {
            isServer = true;
            for (int i = 2; i < argc; i++) {
                argv[i - 1] = argv[i];
            }
            argc--;
        }
        if (strcmp(argv[1], "help") == 0) {
            usage(stdout, argv[0]);
            rv = EXIT_SUCCESS;
            goto error;
        }
    }

    // check remaining params
    if (argc <= 1) {
        if (!isServer) {
            fprintf(stdout, "(type '%s help' for usage)\n\n", argv[0]);
            fprintf(stdout, "OK running client with default secret!\n....\n\n");
        } else {
            fprintf(stdout, "OK running server with default secret!\n....\n\n");
        }
    } else {
        fprintf(stderr, "Too many arguments given\n\n");
        usage(stderr, argv[0]);
        goto error;
    }

    if (isServer) {
        rv = start_server();
    } else {
        rv = start_client();
    }

error:
    if (rv != 0) {
        fprintf(stderr, "Portknock exited with error %d\n", rv);
        rv = EXIT_FAILURE;
    } else {
        rv = EXIT_SUCCESS;
    }

    return rv;
}
