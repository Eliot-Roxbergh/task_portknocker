#ifndef H_PORTKNOCK_SERVER
#define H_PORTKNOCK_SERVER

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int listen_udp_secret(const char *);
int listen_tls_session(void);

/*
 * Maintain whitelist of approved IP addresses
 * A client is whitelisted for TLS by performing portknock
 */
typedef struct {
    unsigned long *addr;
    size_t elems;
} whitelist;

bool client_in_whitelist(unsigned long);
int add_client_to_whitelist(unsigned long);

#endif
