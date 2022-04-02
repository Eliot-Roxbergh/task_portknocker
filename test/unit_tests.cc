#include <gtest/gtest.h>

extern "C" {
#include "client.h"
#include "helper.h"
#include "portknock.h"
#include "server.h"
}

TEST(Portknock, ClientServer)
{
    /* TODO implement concurrent tests */

    /* Default key should work */
    // EXPECT_EQ(0, start_client(NULL));
    // EXPECT_EQ(0, start_server(NULL));
}

TEST(Portknock, KeyParse)
{
    EXPECT_FALSE(is_secret_ok(""));
    EXPECT_TRUE(is_secret_ok("0xC0FFEE"));
    EXPECT_EQ(0xBEEF, get_secret_int("0xBEEF"));
    EXPECT_NE(0xEEF, get_secret_int("0xBEEF"));
}
