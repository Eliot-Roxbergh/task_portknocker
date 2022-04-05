#include <gtest/gtest.h>
#include <pthread.h>

extern "C" {
#include "client.h"
#include "helper.h"
#include "portknock.h"
#include "server.h"
}

void *threaded_server(void *);
void run_client_server(const char *, const char *, int *, int *);

/*
 * Proof of concept.. of course many more tests can be added
 */

/* Unit tests */

TEST(Portknock, FullClientServer)
{
    /*
     * Test base functionality,
     * by having a client knock and then try access
     * the TLS server.
     *
     * TODO this is more of a full application test,
     * the idea is to split into several smaller units and cases!
     */
    const char *secret_s, *secret_c;
    int ret_s, ret_c;

    /* Default key should work */
    secret_s = NULL;
    secret_c = NULL;
    run_client_server(secret_s, secret_c, &ret_s, &ret_c);
    EXPECT_EQ(0, ret_s);
    EXPECT_EQ(0, ret_c);

    /* Default key should match itself */
    secret_s = NULL;
    secret_c = get_secret_str(NULL);
    run_client_server(secret_s, secret_c, &ret_s, &ret_c);
    EXPECT_EQ(0, ret_s);
    EXPECT_EQ(0, ret_c);

    /* Error: Secret mismatch */
    secret_s = "0xC0FFEE";
    secret_c = "0xBEEF";
    run_client_server(secret_s, secret_c, &ret_s, &ret_c);
    EXPECT_NE(0, ret_s);
    EXPECT_NE(0, ret_c);
}

TEST(Portknock, KeyParse)
{
    EXPECT_FALSE(is_secret_ok(""));
    EXPECT_TRUE(is_secret_ok("0xC0FFEE"));
    EXPECT_EQ(0xBEEF, get_secret_int("0xBEEF"));
    EXPECT_NE(0xEEF, get_secret_int("0xBEEF"));
}

/* Helper functions for concurrent client-server tests */

void *threaded_server(void *secret) { return (void *)start_server((const char *)secret); }
void run_client_server(const char *secret_s, const char *secret_c, int *ret_s, int *ret_c)
{
    intptr_t retval_s, retval_c;
    pthread_t server_thread;

    pthread_create(&server_thread, NULL, threaded_server, (void *)secret_s);

    // Wait for server,
    //  because if we send before the socket is ready our listener will deadlock on recvfrom
    usleep(1000); /* ugly hack */
    retval_c = start_client(secret_c);

    pthread_join(server_thread, (void **)&retval_s);

    *ret_s = (int)retval_s;
    *ret_c = (int)retval_c;
}
