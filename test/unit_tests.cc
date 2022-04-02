#include <gtest/gtest.h>

extern "C" {
#include "client.h"
#include "helper.h"
#include "portknock.h"
#include "server.h"
}

TEST(Portknocker, UnitTests)
{
    /* TODO implement concurrent tests */

    /* Default key should work */
    // EXPECT_EQ(0, start_client());
    // EXPECT_EQ(0, start_server());
}
