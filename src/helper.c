#include "helper.h"
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * [improvement] suggestion:
 *  get_secret_str could easily be modified to allow for case insensitive secrets, or not starting with 0x
 */

/*
 * Functions to get and check secret.
 *
 * Secret may be NULL,
 * in which case the hardcoded secret key is used.
 */

/* TODO it is a bit dangerous to have recursive calls like this.
 *      As is now, it should not be a problem but this is a bit funny sequence..
 *      get_secret_int -> get_secret_str -> is_secret_ok -> get_secret_int -> (OK done)
 */
/* Note: returns 0 on error, 0 is not a valid secret */
uint32_t get_secret_int(const char *secret_s)
{
    unsigned long secret;
    errno = 0;

    if (!secret_s) {
        secret_s = get_secret_str(secret_s);
    }

    secret = strtoul(secret_s, NULL, 16);  // hex
    if (errno != 0) {
        perror("Secret key misconfiguration: ");
        goto error;
    }
    if (secret > UINT32_MAX) {
        fprintf(stderr, "Secret key misconfiguration, key too large\n");
        goto error;
    }
    if (secret == 0) {
        fprintf(stderr, "Secret cannot be 0\n");
        goto error;
    }

    return (uint32_t)secret;
error:
    return 0;
}

/* Validate given secret or, if NULL, fallback to harcoded value */
const char *get_secret_str(const char *secret)
{
    if (!secret) {
        secret = SECRET_KEY;
    }

    if (!is_secret_ok(secret)) {
        exit(EXIT_FAILURE);
    }

    return secret;
}

bool is_secret_ok(const char *secret)
{
    uint32_t s = get_secret_int(secret);
    return s != 0;
}
