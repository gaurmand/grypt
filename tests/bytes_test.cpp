#include "testutil.h"

#include <array>
#include <grypt/bytes.h>
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>

using namespace grypt;
using namespace grypt::literals;
using namespace std::literals;

TEST(bytes, bytesViewDefault)
{
   EXPECT_EQ(BytesView{}.size(), 0);
   EXPECT_EQ(BytesView{}, BytesView{""});
}

TEST(bytes, bytesViewFromString)
{
   BytesView bv{"abc"};

   EXPECT_EQ(bv.size(), 3);
   EXPECT_EQ(bv[0], std::byte{'a'});
   EXPECT_EQ(bv[1], std::byte{'b'});
   EXPECT_EQ(bv[2], std::byte{'c'});

   EXPECT_EQ(bv, BytesView{"abc"sv});
   EXPECT_EQ(bv, BytesView{"abc"s});
}

TEST(bytes, bytesViewFromArray)
{
   auto arr = std::array{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
   BytesView bv{arr};
   EXPECT_EQ(bv, BytesView{"abc"});
}

TEST(bytes, bytesViewFromVector)
{
   auto vec = std::vector{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
   BytesView bv{vec};
   EXPECT_EQ(bv, BytesView{"abc"});
}

TEST(bytes, bytesViewCopying)
{
   BytesView bv1{"abc"};
   BytesView bv2{bv1};
   EXPECT_EQ(bv1, bv2);

   bv1 = BytesView{"def"};
   EXPECT_EQ(bv1, BytesView{"def"});
}

TEST(bytes, bytesViewDangling)
{
   auto str = "abcdefghi"sv;
   auto res = std::ranges::find(BytesView{str}, std::byte{'e'});
   EXPECT_EQ(*res, std::byte{'e'});
}

TEST(bytes, bytesDefault)
{
   EXPECT_EQ(Bytes{}.size(), 0);
   EXPECT_EQ(Bytes{}, Bytes{""});
}

TEST(bytes, bytesFromString)
{
   Bytes b{"abc"};

   EXPECT_EQ(b.size(), 3);
   EXPECT_EQ(b[0], std::byte{'a'});
   EXPECT_EQ(b[1], std::byte{'b'});
   EXPECT_EQ(b[2], std::byte{'c'});

   EXPECT_EQ(b, Bytes{"abc"sv});
   EXPECT_EQ(b, Bytes{"abc"s});
}

TEST(bytes, bytesCopying)
{
   Bytes b1{"abc"};
   Bytes b2{b1};
   EXPECT_EQ(b1, b2);

   b1 = Bytes{"def"};
   EXPECT_EQ(b1, Bytes{"def"});
}

TEST(bytes, bytesCountConstructor)
{
   // Note: String constructors that take a single const char* argument assume
   // its null terminated, which is a problem if there are multiple null chars.
   std::string_view nulls("\0\0\0", 3);
   EXPECT_EQ(Bytes(3), Bytes{nulls});

   EXPECT_EQ(Bytes(5, std::byte{'i'}), Bytes{"iiiii"});
}

TEST(bytes, bytesInitializerListConstructor)
{
   EXPECT_EQ(Bytes({std::byte{'a'}, std::byte{'b'}, std::byte{'c'}}),
             Bytes{"abc"});
}

TEST(bytes, bytesViewComparison)
{
   EXPECT_EQ(BytesView{"abc"}, BytesView{"abc"});
   EXPECT_NE(BytesView{"abc"}, BytesView{"bac"});
   EXPECT_LT(BytesView{"ab"}, BytesView{"abc"});
   EXPECT_LE(BytesView{"aba"}, BytesView{"abc"});
   EXPECT_GT(BytesView{"af"}, BytesView{"abc"});
   EXPECT_GE(BytesView{"abq"}, BytesView{"abc"});
}

TEST(bytes, bytesToBytesViewImplicit)
{
   Bytes b{"abc"};
   BytesView bv = b;
   EXPECT_EQ(bv, BytesView{"abc"});
}

TEST(bytes, bytesFromBytesViewExplicit)
{
   Bytes b{BytesView{"def"}};
   EXPECT_EQ(b, Bytes{"def"});
}

TEST(bytes, bytesComparison)
{
   EXPECT_EQ(Bytes{"abc"}, Bytes{"abc"});
   EXPECT_NE(Bytes{"abc"}, Bytes{"bac"});
   EXPECT_LT(Bytes{"ab"}, Bytes{"abc"});
   EXPECT_LE(Bytes{"aba"}, Bytes{"abc"});
   EXPECT_GT(Bytes{"af"}, Bytes{"abc"});
   EXPECT_GE(Bytes{"abq"}, Bytes{"abc"});
}

TEST(bytes, bytesAndBytesViewComparison)
{
   EXPECT_EQ(Bytes{"abc"}, BytesView{"abc"});
   EXPECT_NE(BytesView{"abc"}, Bytes{"bac"});
   EXPECT_LT(Bytes{"ab"}, BytesView{"abc"});
   EXPECT_LE(BytesView{"aba"}, Bytes{"abc"});
   EXPECT_GT(Bytes{"af"}, BytesView{"abc"});
   EXPECT_GE(BytesView{"abq"}, Bytes{"abc"});
}

TEST(bytes, bytesLiterals)
{
   EXPECT_EQ("abc"_bv, BytesView{"abc"});
   EXPECT_EQ("abc"_b, Bytes{"abc"});
}

TEST(bytes, toHex)
{
   EXPECT_EQ(BytesView{"abc"}.toHex(), "0x616263"sv);
   EXPECT_EQ(Bytes{"KLM"}.toHex(), "0x4b4c4d"sv);
   EXPECT_EQ(Bytes{""}.toHex(), ""sv);
}

TEST(bytes, fromHex)
{
   // 0x, 0X, & no prefix should have the same result
   EXPECT_EQ(Bytes::fromHex("0x616263"), BytesView{"abc"});
   EXPECT_EQ(Bytes::fromHex("0X616263"), BytesView{"abc"});
   EXPECT_EQ(Bytes::fromHex("616263"), BytesView{"abc"});

   // Upper & lower case should have the same result
   EXPECT_EQ(Bytes::fromHex("0x4b4c4d"), BytesView{"KLM"});
   EXPECT_EQ(Bytes::fromHex("0x4B4C4D"), BytesView{"KLM"});

   // If odd num chars, same result as prefixing 0.
   EXPECT_EQ(Bytes::fromHex("0x070809"), BytesView{"\a\b\t"});
   EXPECT_EQ(Bytes::fromHex("0x70809"), BytesView{"\a\b\t"});

   EXPECT_EQ(Bytes::fromHex(""), BytesView{""});
}

TEST(bytes, bytesDataAccess)
{
   Bytes b{"abc"};

   std::byte* data = b.data();
   EXPECT_EQ(BytesView{std::span<std::byte>(data, 3)}, BytesView{"abc"});

   unsigned char* udata = b.udata();
   EXPECT_TRUE(
      std::ranges::equal(std::span<unsigned char>(udata, 3),
                         std::array<unsigned char, 3>{0x61, 0x62, 0x63}));
}

TEST(bytes, bytesViewDataAccess)
{
   BytesView b{"abc"};

   const std::byte* data = b.data();
   EXPECT_EQ(BytesView{std::span<const std::byte>(data, 3)}, BytesView{"abc"});

   const unsigned char* udata = b.udata();
   EXPECT_TRUE(
      std::ranges::equal(std::span<const unsigned char>(udata, 3),
                         std::array<unsigned char, 3>{0x61, 0x62, 0x63}));
}

TEST(bytes, io)
{
   std::stringstream ss;

   ss << Bytes{"abc"};
   EXPECT_EQ(ss.str(), "0x616263"sv);

   Bytes b;
   ss >> b;
   EXPECT_EQ(b, Bytes{"abc"});
}

TEST(bytes, ioSingleHexChars)
{
   // Ensure bytes that converted to single hex chars are prepended with 0's
   Bytes b{std::byte{0xa}, std::byte{0xb}, std::byte{0xc}};

   std::stringstream ss;
   ss << b;
   EXPECT_EQ(ss.str(), "0x0a0b0c"sv);
}

TEST(bytes, concat)
{
   EXPECT_EQ(Bytes{"ab"} += Bytes{"cd"}, "abcd"_bv);
   EXPECT_EQ(Bytes{"ab"} += BytesView{"cd"}, "abcd"_bv);

   EXPECT_EQ(Bytes{"ab"} + Bytes{"cd"}, "abcd"_bv);
   EXPECT_EQ(Bytes{"ab"} + BytesView{"cd"}, "abcd"_bv);
   EXPECT_EQ(BytesView{"ab"} + Bytes{"cd"}, "abcd"_bv);
   EXPECT_EQ(BytesView{"ab"} + BytesView{"cd"}, "abcd"_bv);
}
