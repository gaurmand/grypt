#include "testutil.h"

#include <grypt/algorithm.h>
#include <grypt/mac.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace grypt;
using namespace grypt::literals;

using Alg  = MAC::Algorithm;
using Info = MAC::AlgorithmInfo;
using HAlg = HashAlgorithm;
using CAlg = CMACAlgorithm;
using GAlg = GMACAlgorithm;

testing::AssertionResult basicTest(std::expected<MAC, Error> mac)
{
   if (!mac.has_value())
   {
      return testing::AssertionFailure() << "mac creation failed";
   }

   auto tag = mac->sign(kTestPlaintext);
   if (!tag.has_value())
   {
      return testing::AssertionFailure() << "sign failed";
   }

   auto res = mac->verify(kTestPlaintext, tag.value());
   if (!res.has_value())
   {
      return testing::AssertionFailure() << "verify failed";
   }
   if (res.value() == false)
   {
      return testing::AssertionFailure() << "verify returned false";
   }

   return testing::AssertionSuccess();
}

testing::AssertionResult authTest(std::expected<MAC, Error> mac)
{
   if (!mac.has_value())
   {
      return testing::AssertionFailure() << "mac creation failed";
   }

   auto tag = mac->sign(kTestPlaintext);
   if (!tag.has_value())
   {
      return testing::AssertionFailure() << "sign failed";
   }

   Bytes tampered{kTestPlaintext};
   tampered.at(4) = std::byte{7};

   auto res = mac->verify(tampered, tag.value());
   if (!res.has_value())
   {
      return testing::AssertionFailure() << "verify failed";
   }
   if (res.value() == true)
   {
      return testing::AssertionFailure()
             << "tampered plaintext was not detected";
   }

   return testing::AssertionSuccess();
}

TEST(mac, basic)
{
   // HMAC requires hash alg
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::BLAKE2B_512)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::BLAKE2S_256)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::RIPEMD_160)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::MD5)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::MD5_SHA1)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA1)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA2_224)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA2_256)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA2_384)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA2_512)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA2_512_224)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA2_512_256)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA3_224)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA3_256)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA3_384)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHA3_512)));
   EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SM3)));

   // EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::KECCAK_KMAC_128)));
   // EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::KECCAK_KMAC_256)));
   // EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHAKE_128)));
   // EXPECT_TRUE(basicTest(MAC::createHMAC(kTestKey, HAlg::SHAKE_256)));

   // BLAKE2SMAC key size must be 1-32 bytes
   // BLAKE2BMAC key size must be 1-64 bytes
   EXPECT_TRUE(basicTest(MAC::create(Bytes(32), Alg::BLAKE2SMAC)));
   EXPECT_TRUE(basicTest(MAC::create(Bytes(64), Alg::BLAKE2BMAC)));

   // Key must be 4-512 bytes
   EXPECT_TRUE(basicTest(MAC::create(kTestKey, Alg::KMAC_128)));
   EXPECT_TRUE(basicTest(MAC::create(kTestKey, Alg::KMAC_256)));

   // CMAC requires CBC cipher alg
   // Key must be exactly cipher key size
   EXPECT_TRUE(basicTest(MAC::createCMAC(Bytes(16), CAlg::AES_128_CBC)));
   EXPECT_TRUE(basicTest(MAC::createCMAC(Bytes(24), CAlg::AES_192_CBC)));
   EXPECT_TRUE(basicTest(MAC::createCMAC(Bytes(32), CAlg::AES_256_CBC)));

   // GMAC require GCM cipher alg
   // Key size must be exact, but not iv size?
   EXPECT_TRUE(
      basicTest(MAC::createGMAC(Bytes(16), Bytes(12), GAlg::AES_128_GCM)));
   EXPECT_TRUE(
      basicTest(MAC::createGMAC(Bytes(24), Bytes(12), GAlg::AES_192_GCM)));
   EXPECT_TRUE(
      basicTest(MAC::createGMAC(Bytes(32), Bytes(12), GAlg::AES_256_GCM)));

   // Key size must be 16
   EXPECT_TRUE(basicTest(MAC::create(Bytes(16), Alg::SIPHASH)));

   // EXPECT_TRUE(basicTest(Alg::Poly1305, {}, {}, {}, Bytes(32)));
}

TEST(mac, auth)
{
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::BLAKE2B_512)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::BLAKE2S_256)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::RIPEMD_160)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::MD5)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::MD5_SHA1)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA1)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA2_224)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA2_256)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA2_384)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA2_512)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA2_512_224)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA2_512_256)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA3_224)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA3_256)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA3_384)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SHA3_512)));
   EXPECT_TRUE(authTest(MAC::createHMAC(kTestKey, HAlg::SM3)));

   EXPECT_TRUE(authTest(MAC::create(Bytes(32), Alg::BLAKE2SMAC)));
   EXPECT_TRUE(authTest(MAC::create(Bytes(64), Alg::BLAKE2BMAC)));

   EXPECT_TRUE(authTest(MAC::create(kTestKey, Alg::KMAC_128)));
   EXPECT_TRUE(authTest(MAC::create(kTestKey, Alg::KMAC_256)));

   EXPECT_TRUE(authTest(MAC::createCMAC(Bytes(16), CAlg::AES_128_CBC)));
   EXPECT_TRUE(authTest(MAC::createCMAC(Bytes(24), CAlg::AES_192_CBC)));
   EXPECT_TRUE(authTest(MAC::createCMAC(Bytes(32), CAlg::AES_256_CBC)));

   EXPECT_TRUE(
      authTest(MAC::createGMAC(Bytes(16), Bytes(12), GAlg::AES_128_GCM)));
   EXPECT_TRUE(
      authTest(MAC::createGMAC(Bytes(24), Bytes(12), GAlg::AES_192_GCM)));
   EXPECT_TRUE(
      authTest(MAC::createGMAC(Bytes(32), Bytes(12), GAlg::AES_256_GCM)));

   EXPECT_TRUE(authTest(MAC::create(Bytes(16), Alg::SIPHASH)));
}

TEST(mac, multiSign)
{
   auto mac = MAC::createHMAC(kTestKey, HAlg::SHA2_256);
   ASSERT_TRUE(mac.has_value());

   auto t1 = mac->sign(kTestPlaintext);
   ASSERT_TRUE(t1.has_value());

   auto v1 = mac->verify(kTestPlaintext, t1.value());
   ASSERT_TRUE(v1.has_value());
   EXPECT_TRUE(v1.value());

   auto t2 = mac->sign(kTestPlaintext2);
   ASSERT_TRUE(t2.has_value());

   auto v2 = mac->verify(kTestPlaintext2, t2.value());
   ASSERT_TRUE(v2.has_value());
   EXPECT_TRUE(v2.value());
}

TEST(mac, multiStepSign)
{
   auto mac = MAC::createGMAC(Bytes(32), Bytes(12), GAlg::AES_256_GCM);
   ASSERT_TRUE(mac.has_value());

   auto init = mac->macInit();
   ASSERT_TRUE(init.has_value());

   const auto data   = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto chunks = data | std::views::chunk(12);

   auto m1 = mac->macUpdate(BytesView{chunks[0]});
   ASSERT_TRUE(m1.has_value());
   auto m2 = mac->macUpdate(BytesView{chunks[1]});
   ASSERT_TRUE(m2.has_value());
   auto m3 = mac->macUpdate(BytesView{chunks[2]});
   ASSERT_TRUE(m3.has_value());

   auto t1 = mac->macFinal();
   ASSERT_TRUE(t1.has_value());

   auto t2 = mac->sign(data);
   ASSERT_TRUE(t2.has_value());

   EXPECT_EQ(t1.value(), t2.value());
}

TEST(mac, lowLevelOperationsAbuse)
{
   auto mac = MAC::create(kTestKey, Alg::KMAC_128);
   ASSERT_TRUE(mac.has_value());

   // Errors from uninitialized state
   EXPECT_EQ(mac->macUpdate({}).error(), ErrorCode::MACUpdateNotAllowed);
   EXPECT_EQ(mac->macFinal().error(), ErrorCode::MACFinalNotAllowed);

   // Errors from in progress state
   EXPECT_TRUE(mac->macInit().has_value());
   EXPECT_EQ(mac->macFinal().error(), ErrorCode::MACFinalNotAllowed);
}
