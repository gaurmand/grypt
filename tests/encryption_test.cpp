#include <encryption.h>
#include <gtest/gtest.h>

using namespace grypt;

TEST(basic, basicTest)
{
   Encryption e{"abc"};
   EXPECT_TRUE(e.encrypt("cde").has_value());
   EXPECT_TRUE(e.decrypt("ghi").has_value());
}
