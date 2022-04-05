#include "portknock.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * [improvement] suggestions:
 *  - Take more inputs, such as server IP (for client) and ports to use.
 *
 *  - Another additional feature would be to have timeout, retry, etc.
 */

void usage(FILE *stream, const char *prog)
{
    fprintf(stream, "Usage: %s [help] [server] [<secret_key>]\n", prog);
    fprintf(stream, "With no args, client is started with default config\n\n");
}

int main(int argc, char **argv)
{
    int rv = -1;
    const char *secret = NULL;
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

    // get secret if given
    if (argc <= 1) {
        if (!isServer) {
            fprintf(stdout, "(type '%s help' for usage)\n\n", argv[0]);
            fprintf(stdout, "No args, OK running client with default secret!\n....\n\n");
        } else {
            fprintf(stdout, "OK running server with default secret!\n....\n\n");
        }
    } else if (argc == 2) {
        secret = argv[1];
        if (secret[0] == '\0') {
            fprintf(stderr, "Secret given, but empty!\n\n");
            goto error;
        }
        fprintf(stdout, "Starting %s. Using secret given from command line!\n....\n\n", isServer ? "server" : "client");
    } else {
        fprintf(stderr, "%d too many arguments given\n\n", argc - 2);
        usage(stderr, argv[0]);
        goto error;
    }

    if (isServer) {
        rv = start_server(secret);
    } else {
        rv = start_client(secret);
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
