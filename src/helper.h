#ifndef H_PORTKNOCK_HELPER
#define H_PORTKNOCK_HELPER

#include <stdbool.h>
#include <stdint.h>

#define BUF_LEN 256
/* Server "password" */
#define SECRET_KEY "0x3C0F"
/* Server response */
#define ACK_MSG "Welcome!"
#define BAD_MSG "Client authentication failed!"  // wrong secret

/* Use this interface to get the secret key.
 *
 *  Thereby, we can check that the key is "valid".
 *  This also enables us to do more advanced things in the future for the sent secret.
 *   For instance, we could fetch secret from file, derive a temporary key from the secret, etc.
 */
uint32_t get_secret_int(const char*);
const char* get_secret_str(const char*);
bool is_secret_ok(const char*);

#endif
