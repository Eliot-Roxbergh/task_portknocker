#include <gtest/gtest.h>
#include <pthread.h>

extern "C" {
#include "client.h"
#include "helper.h"
#include "portknock.h"
#include "server.h"
}

/* Helper functions for concurrent client-server tests */

void *threaded_udp_server(void *secret) { return (void *)listen_udp_secret((const char *)secret); }
void test_udp(const char *secret_s, const char *secret_c, int *ret_s, int *ret_c)
{
    intptr_t retval_s, retval_c;
    pthread_t server_thread;

    pthread_create(&server_thread, NULL, threaded_udp_server, (void *)secret_s);

    // Wait for server,
    //  because if we send before the socket is ready our listener will deadlock on recvfrom
    usleep(1000); /* ugly hack */
    retval_c = send_udp_secret(secret_c);

    pthread_join(server_thread, (void **)&retval_s);

    *ret_s = (int)retval_s;
    *ret_c = (int)retval_c;
}

void *threaded_tls_server(void *arg)
{
    (void)arg;
    return (void *)listen_tls_session();
}
void test_tls(int *ret_s, int *ret_c)
{
    intptr_t retval_s, retval_c;
    pthread_t server_thread;

    pthread_create(&server_thread, NULL, threaded_tls_server, NULL);

    // Wait for server,
    //  because if we send before the socket is ready the server will wait forever for the lost message
    //  (client fails on connect() but server does not realize this)
    sleep(1); /* ugly hack */

    retval_c = start_tls_session();
    pthread_join(server_thread, (void **)&retval_s);

    *ret_s = (int)retval_s;
    *ret_c = (int)retval_c;
}

/* Unit tests */

TEST(Portknock, UDP_ClientServer)
{
    /* Test UDP two-way communication */
    const char *secret_s, *secret_c;
    int ret_s, ret_c;

    /* Default key should work */
    secret_s = NULL;
    secret_c = NULL;
    test_udp(secret_s, secret_c, &ret_s, &ret_c);
    EXPECT_EQ(0, ret_s);
    EXPECT_EQ(0, ret_c);

    /* Default key should match itself */
    secret_s = NULL;
    secret_c = get_secret_str(NULL);
    test_udp(secret_s, secret_c, &ret_s, &ret_c);
    EXPECT_EQ(0, ret_s);
    EXPECT_EQ(0, ret_c);

    /* Error: Secret mismatch */
    secret_s = "0xC0FFEE";
    secret_c = "0xBEEF";
    test_udp(secret_s, secret_c, &ret_s, &ret_c);
    EXPECT_NE(0, ret_s);
    EXPECT_NE(0, ret_c);
}

TEST(Portknock, TLS_ClientServer)
{
    /* Test TLS two-way communication */
    int ret_s, ret_c;

    test_tls(&ret_s, &ret_c);
    EXPECT_EQ(0, ret_s);
    EXPECT_EQ(0, ret_c);
}

TEST(Portknock, KeyParse)
{
    EXPECT_FALSE(is_secret_ok(""));
    EXPECT_TRUE(is_secret_ok("0xC0FFEE"));
    EXPECT_EQ(0xBEEF, get_secret_int("0xBEEF"));
    EXPECT_NE(0xEEF, get_secret_int("0xBEEF"));
}
