#include "helper.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

uint32_t secret_key_int(void)
{
    errno = 0;
    unsigned long secret = strtoul(SECRET_KEY, NULL, 16);
    if (errno != 0) {
        perror("Secret key misconfiguration: ");
        goto error;
    }
    if (secret > UINT32_MAX) {
        fprintf(stderr, "Secret key misconfiguration, key too large");
        goto error;
    }

    return (uint32_t)secret;
error:
    exit(EXIT_FAILURE);
}

const char* secret_key_str(void)
{
    /* check for parse errors */
    (void)secret_key_int();

    return SECRET_KEY;
}
