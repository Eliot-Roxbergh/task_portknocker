#ifndef H_PORTKNOCK_HELPER
#define H_PORTKNOCK_HELPER

#include <stdint.h>

/* Server "password" */
#define SECRET_KEY "0x3C0F"
/* Server response */
#define ACK_MSG "Welcome!"

/* Use this interface to get the secret key.
 *
 *  Thereby, we can check that the key is "valid".
 *  This also enables us to do more advanced things in the future for the sent secret.
 *   For instance, we could fetch secret from file, derive a temporary key from the secret, etc.
 */
uint32_t secret_key_int(void);
const char* secret_key_str(void);

#endif
