#include "testutil.h"

#include <grypt/hash.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace grypt;
using namespace grypt::literals;

using Alg  = Hash::Algorithm;
using Info = Hash::AlgorithmInfo;

namespace
{

}

testing::AssertionResult basicTest(Alg alg)
{
   auto hash = Hash::create(alg);
   if (!hash.has_value())
   {
      return testing::AssertionFailure() << "cipher creation failed";
   }

   auto digest = hash->digest(kTestPlaintext);
   if (!digest.has_value())
   {
      return testing::AssertionFailure() << "digest failed";
   }

   return testing::AssertionSuccess();
}

testing::AssertionResult knownAnswerTest(Alg alg, BytesView expectedDigest)
{
   static const BytesView kHashData =
      "The quick brown fox jumps over the lazy dog"_bv;

   auto hash = Hash::create(alg);
   if (!hash.has_value())
   {
      return testing::AssertionFailure() << "cipher creation failed";
   }

   auto digest = hash->digest(kHashData);
   if (!digest.has_value())
   {
      return testing::AssertionFailure() << "encryption failed";
   }

   if (digest.value() != expectedDigest)
   {
      return testing::AssertionFailure() << "digest != expected digest";
   }

   return testing::AssertionSuccess();
}

TEST(hash, basic)
{
   EXPECT_TRUE(basicTest(Alg::BLAKE2S_256));
   EXPECT_TRUE(basicTest(Alg::BLAKE2B_512));
   EXPECT_TRUE(basicTest(Alg::MD5));
   EXPECT_TRUE(basicTest(Alg::MD5_SHA1));
   EXPECT_TRUE(basicTest(Alg::RIPEMD_160));
   EXPECT_TRUE(basicTest(Alg::SHA1));
   EXPECT_TRUE(basicTest(Alg::SHA2_224));
   EXPECT_TRUE(basicTest(Alg::SHA2_256));
   EXPECT_TRUE(basicTest(Alg::SHA2_384));
   EXPECT_TRUE(basicTest(Alg::SHA2_512));
   EXPECT_TRUE(basicTest(Alg::SHA2_512_224));
   EXPECT_TRUE(basicTest(Alg::SHA2_512_256));
   EXPECT_TRUE(basicTest(Alg::SHA3_224));
   EXPECT_TRUE(basicTest(Alg::SHA3_256));
   EXPECT_TRUE(basicTest(Alg::SHA3_384));
   EXPECT_TRUE(basicTest(Alg::SHA3_512));
   EXPECT_TRUE(basicTest(Alg::SHAKE_128));
   EXPECT_TRUE(basicTest(Alg::SHAKE_256));
   EXPECT_TRUE(basicTest(Alg::KECCAK_KMAC_128));
   EXPECT_TRUE(basicTest(Alg::KECCAK_KMAC_256));
   EXPECT_TRUE(basicTest(Alg::SM3));
}

TEST(hash, info)
{
   // Some algs allows arbitray output length, we just use the default for now
   EXPECT_EQ(Hash::create(Alg::BLAKE2S_256)->info().digestLength, 32);
   EXPECT_EQ(Hash::create(Alg::BLAKE2B_512)->info().digestLength, 64);
   EXPECT_EQ(Hash::create(Alg::MD5)->info().digestLength, 16);
   EXPECT_EQ(Hash::create(Alg::MD5_SHA1)->info().digestLength, 36);
   EXPECT_EQ(Hash::create(Alg::RIPEMD_160)->info().digestLength, 20);
   EXPECT_EQ(Hash::create(Alg::SHA1)->info().digestLength, 20);
   EXPECT_EQ(Hash::create(Alg::SHA2_224)->info().digestLength, 28);
   EXPECT_EQ(Hash::create(Alg::SHA2_256)->info().digestLength, 32);
   EXPECT_EQ(Hash::create(Alg::SHA2_384)->info().digestLength, 48);
   EXPECT_EQ(Hash::create(Alg::SHA2_512)->info().digestLength, 64);
   EXPECT_EQ(Hash::create(Alg::SHA2_512_224)->info().digestLength, 28);
   EXPECT_EQ(Hash::create(Alg::SHA2_512_256)->info().digestLength, 32);
   EXPECT_EQ(Hash::create(Alg::SHA3_224)->info().digestLength, 28);
   EXPECT_EQ(Hash::create(Alg::SHA3_256)->info().digestLength, 32);
   EXPECT_EQ(Hash::create(Alg::SHA3_384)->info().digestLength, 48);
   EXPECT_EQ(Hash::create(Alg::SHA3_512)->info().digestLength, 64);
   EXPECT_EQ(Hash::create(Alg::KECCAK_KMAC_128)->info().digestLength, 32);
   EXPECT_EQ(Hash::create(Alg::KECCAK_KMAC_256)->info().digestLength, 64);
   EXPECT_EQ(Hash::create(Alg::SM3)->info().digestLength, 32);
   EXPECT_EQ(Hash::create(Alg::SHAKE_128)->info().digestLength, 16);
   EXPECT_EQ(Hash::create(Alg::SHAKE_256)->info().digestLength, 32);
}

TEST(hash, knownAnswers)
{
   EXPECT_TRUE(knownAnswerTest(
      Alg::BLAKE2B_512,
      Bytes::fromHex(
         "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f8240"
         "1cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918")));

   EXPECT_TRUE(knownAnswerTest(
      Alg::MD5, Bytes::fromHex("9e107d9d372bb6826bd81d3542a419d6")));

   EXPECT_TRUE(knownAnswerTest(
      Alg::SHA1, Bytes::fromHex("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")));

   EXPECT_TRUE(knownAnswerTest(
      Alg::SHA2_256,
      Bytes::fromHex(
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")));

   EXPECT_TRUE(knownAnswerTest(
      Alg::SHA3_256,
      Bytes::fromHex(
         "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04")));

   EXPECT_TRUE(knownAnswerTest(
      Alg::SHAKE_128, Bytes::fromHex("f4202e3c5852f9182a0430fd8144f0a7")));
}

TEST(hash, multiHash)
{
   auto hash = Hash::create(Alg::SHA1);
   ASSERT_TRUE(hash.has_value());

   ASSERT_TRUE(hash->digest(kTestPlaintext).has_value());
   ASSERT_TRUE(hash->digest(kTestPlaintext).has_value());
   ASSERT_TRUE(hash->digest(kTestPlaintext).has_value());
}

TEST(hash, multiStepHash)
{
   auto hash = Hash::create(Alg::SHA2_256);
   ASSERT_TRUE(hash.has_value());

   auto init = hash->digestInit();
   ASSERT_TRUE(init.has_value());

   const auto data   = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto chunks = data | std::views::chunk(12);

   auto d1 = hash->digestUpdate(BytesView{chunks[0]});
   ASSERT_TRUE(d1.has_value());
   auto d2 = hash->digestUpdate(BytesView{chunks[1]});
   ASSERT_TRUE(d2.has_value());
   auto d3 = hash->digestUpdate(BytesView{chunks[2]});
   ASSERT_TRUE(d3.has_value());

   auto partsDigest = hash->digestFinal();
   ASSERT_TRUE(partsDigest.has_value());

   auto fullDigest = hash->digest(data);
   ASSERT_TRUE(fullDigest.has_value());

   EXPECT_EQ(partsDigest.value(), fullDigest.value());
}

TEST(hash, lowLevelOperationsAbuse)
{
   auto hash = Hash::create(Alg::SHA3_256);

   // Errors from uninitialized state
   EXPECT_EQ(hash->digestUpdate({}).error(), ErrorCode::DigestUpdateNotAllowed);
   EXPECT_EQ(hash->digestFinal().error(), ErrorCode::DigestFinalNotAllowed);

   // Errors from initialized state
   ASSERT_TRUE(hash->digestInit().has_value());
   EXPECT_EQ(hash->digestFinal().error(), ErrorCode::DigestFinalNotAllowed);
}
