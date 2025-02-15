#include "data.h"
#include "testutil.h"

#include <grypt/algorithm.h>
#include <grypt/digitalsignature.h>
#include <grypt/randombytes.h>
#include <gtest/gtest.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

using namespace grypt;
using namespace grypt::literals;

using DS   = DigitalSignature;
using Alg  = DigitalSignature::Algorithm;
using Info = DigitalSignature::AlgorithmInfo;
using HAlg = HashAlgorithm;
using RSA  = RSAPadding;

testing::AssertionResult basicTest(std::expected<DS, Error> ds)
{
   if (!ds.has_value())
   {
      return testing::AssertionFailure() << "ds creation failed";
   }

   auto tag = ds->sign(Bytes(256));
   if (!tag.has_value())
   {
      return testing::AssertionFailure() << "sign failed";
   }

   auto ver = ds->verify(Bytes(256), tag.value());
   if (!ver.has_value())
   {
      return testing::AssertionFailure() << "verify failed";
   }
   if (ver.value() == false)
   {
      return testing::AssertionFailure() << "verify returned false";
   }

   return testing::AssertionSuccess();
}

testing::AssertionResult authTest(std::expected<DS, Error> ds)
{
   if (!ds.has_value())
   {
      return testing::AssertionFailure() << "ds creation failed";
   }

   auto tag = ds->sign(kTestPlaintext);
   if (!tag.has_value())
   {
      return testing::AssertionFailure() << "sign failed";
   }

   Bytes verifyData{kTestPlaintext};
   verifyData.at(4) = std::byte{7};

   auto ver = ds->verify(verifyData, tag.value());
   if (!ver.has_value())
   {
      return testing::AssertionFailure() << "verify failed";
   }
   if (ver.value() == true)
   {
      return testing::AssertionFailure() << "tampered data not detected";
   }

   return testing::AssertionSuccess();
}

TEST(digitalSignature, basic)
{
   EXPECT_TRUE(basicTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA1)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_224)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_256)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_384)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_512)));

   EXPECT_TRUE(basicTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA1)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_224)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_256)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_384)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_512)));

   EXPECT_TRUE(basicTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA1)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_224)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_256)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_384)));
   EXPECT_TRUE(
      basicTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_512)));

   // ED requires null hash alg
   EXPECT_TRUE(basicTest(DS::createED(Alg::ED25519, kEC25519PrivateKey)));
   EXPECT_TRUE(basicTest(DS::createED(Alg::ED448, kEC448PrivateKey)));

   EXPECT_TRUE(
      basicTest(DS::createRSA(kRSAPrivateKey2048, RSA::PKCS1, HAlg::SHA1)));
   EXPECT_TRUE(
      basicTest(DS::createRSA(kRSAPrivateKey2048, RSA::PSS, HAlg::SHA2_256)));

   // Should be supported according to docs but its not???
   // https://docs.openssl.org/3.0/man3/EVP_DigestSignInit/#description
   // https://github.com/openssl/openssl/blob/master/crypto/rsa/rsa_pmeth.c#L407
   // EXPECT_TRUE(
   //    basicTest(DS::createRSA(kRSAPrivateKey2048, RSA::X931,
   //    HAlg::SHA2_256)));
   // EXPECT_TRUE(
   //    basicTest(DS::createRSA(kRSAPrivateKey2048, RSA::None, std::nullopt)));
}

TEST(digitalSignature, info)
{
   EXPECT_EQ(DS::create(Alg::RSA, kRSAPrivateKey4096, HAlg::SHA1)->info(),
             Info({4096, true}));
   EXPECT_EQ(DS::create(Alg::DSA, kDSAPublicKey2048, HAlg::SHA1)->info(),
             Info({2048, false}));
   EXPECT_EQ(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_256)->info(),
             Info({521, true}));
   EXPECT_EQ(DS::createED(Alg::ED25519, kED25519PublicKey)->info(),
             Info({256, false}));
}

TEST(digitalSignature, tamperData)
{
   EXPECT_TRUE(authTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA1)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_224)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_256)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_384)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_512)));

   EXPECT_TRUE(authTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA1)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_224)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_256)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_384)));
   EXPECT_TRUE(
      authTest(DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA2_512)));

   EXPECT_TRUE(authTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA1)));
   EXPECT_TRUE(authTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_224)));
   EXPECT_TRUE(authTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_256)));
   EXPECT_TRUE(authTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_384)));
   EXPECT_TRUE(authTest(DS::create(Alg::ECDSA, kECPrivateKey, HAlg::SHA2_512)));

   EXPECT_TRUE(authTest(DS::createED(Alg::ED25519, kEC25519PrivateKey)));
   EXPECT_TRUE(authTest(DS::createED(Alg::ED448, kEC448PrivateKey)));

   EXPECT_TRUE(
      authTest(DS::createRSA(kRSAPrivateKey2048, RSA::PKCS1, HAlg::SHA1)));
   EXPECT_TRUE(
      authTest(DS::createRSA(kRSAPrivateKey2048, RSA::PSS, HAlg::SHA2_256)));
}

TEST(digitalSignature, createFromFile)
{
   EXPECT_TRUE(
      DS::create(Alg::DSA, "data/dsa_pub.pem"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(
      DS::create(Alg::DSA, "data/dsa_priv.pem"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(
      DS::create(Alg::DSA, "data/dsa_pub.der"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(
      DS::create(Alg::DSA, "data/dsa_priv.der"_fp, HAlg::SHA2_256).has_value());

   EXPECT_TRUE(
      DS::create(Alg::RSA, "data/rsa_pub.pem"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(
      DS::create(Alg::RSA, "data/rsa_priv.pem"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(
      DS::create(Alg::RSA, "data/rsa_pub.der"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(
      DS::create(Alg::RSA, "data/rsa_priv.der"_fp, HAlg::SHA2_256).has_value());

   EXPECT_TRUE(
      DS::create(Alg::ECDSA, "data/ec_pub.pem"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(DS::create(Alg::ECDSA, "data/ec_priv.pem"_fp, HAlg::SHA2_256)
                  .has_value());
   EXPECT_TRUE(
      DS::create(Alg::ECDSA, "data/ec_pub.der"_fp, HAlg::SHA2_256).has_value());
   EXPECT_TRUE(DS::create(Alg::ECDSA, "data/ec_priv.der"_fp, HAlg::SHA2_256)
                  .has_value());

   EXPECT_TRUE(
      DS::createED(Alg::ED25519, "data/ed25519_priv.pem"_fp).has_value());
   EXPECT_TRUE(
      DS::createED(Alg::ED25519, "data/ed25519_pub.pem"_fp).has_value());
   EXPECT_TRUE(
      DS::createED(Alg::ED25519, "data/ed25519_priv.der"_fp).has_value());
   EXPECT_TRUE(
      DS::createED(Alg::ED25519, "data/ed25519_pub.der"_fp).has_value());

   EXPECT_TRUE(DS::createED(Alg::ED448, "data/ed448_priv.pem"_fp).has_value());
   EXPECT_TRUE(DS::createED(Alg::ED448, "data/ed448_pub.pem"_fp).has_value());
   EXPECT_TRUE(DS::createED(Alg::ED448, "data/ed448_priv.der"_fp).has_value());
   EXPECT_TRUE(DS::createED(Alg::ED448, "data/ed448_pub.der"_fp).has_value());
}

TEST(digitalSignature, multiSign)
{
   auto ds = DS::createED(Alg::ED25519, "data/ed25519_priv.der"_fp);
   ASSERT_TRUE(ds.has_value());

   auto t1 = ds->sign(kTestPlaintext);
   ASSERT_TRUE(t1.has_value());

   auto v1 = ds->verify(kTestPlaintext, t1.value());
   ASSERT_TRUE(v1.has_value());
   EXPECT_TRUE(v1.value());

   auto t2 = ds->sign(kTestPlaintext2);
   ASSERT_TRUE(t2.has_value());

   auto v2 = ds->verify(kTestPlaintext2, t2.value());
   ASSERT_TRUE(v2.has_value());
   EXPECT_TRUE(v2.value());
}

TEST(digitalSignature, multiStepSign)
{
   auto ds = DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_224);
   ASSERT_TRUE(ds.has_value());

   auto init = ds->signInit();
   ASSERT_TRUE(init.has_value());

   const auto data   = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto chunks = data | std::views::chunk(12);

   auto m1 = ds->signUpdate(BytesView{chunks[0]});
   ASSERT_TRUE(m1.has_value());
   auto m2 = ds->signUpdate(BytesView{chunks[1]});
   ASSERT_TRUE(m2.has_value());
   auto m3 = ds->signUpdate(BytesView{chunks[2]});
   ASSERT_TRUE(m3.has_value());

   auto t1 = ds->signFinal();
   ASSERT_TRUE(t1.has_value());

   auto t2 = ds->sign(data);
   ASSERT_TRUE(t2.has_value());

   EXPECT_EQ(t1.value(), t2.value());
}

TEST(digitalSignature, multiStepVerify)
{
   auto ds = DS::create(Alg::RSA, kRSAPrivateKey2048, HAlg::SHA2_224);
   ASSERT_TRUE(ds.has_value());

   auto init = ds->verifyInit();
   ASSERT_TRUE(init.has_value());

   const auto data   = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto chunks = data | std::views::chunk(12);

   auto m1 = ds->verifyUpdate(BytesView{chunks[0]});
   ASSERT_TRUE(m1.has_value());
   auto m2 = ds->verifyUpdate(BytesView{chunks[1]});
   ASSERT_TRUE(m2.has_value());
   auto m3 = ds->verifyUpdate(BytesView{chunks[2]});
   ASSERT_TRUE(m3.has_value());

   auto tag = Bytes::fromHex(
      "0xab959c8047fb22b4598b088014dd5904f75d130c0950923cfefbf8037d3711907880cf"
      "1cf9e146c5e1edbdae062600dd3d8f6d88984491dbb8e5ddf2d34c376629436114e6c753"
      "523e9dc4965771b525dafe9b937f7c2a7eddaf76a08d88c84abb161ad03f746989dcdc4d"
      "317bdeb74bfa9b49529240661716b4883e0e2dcbc163a801f7ed330481de72d4da602737"
      "4daac882becb47520086a526453ad78e6ff5575bc66bafa6b14013f001389a0e5ddfeeca"
      "cca56c5389b79eb392228892f556e5e09bab8db254557c50a07df3e4498a67c76a762de3"
      "69a3172937f9dca55cc6863ab49a5095bbaff01093d6ba000fbd1fe57ed1700cf3d492c6"
      "05dcb4a80f");

   auto t1 = ds->verifyFinal(tag);
   ASSERT_TRUE(t1.has_value());

   auto t2 = ds->verify(data, tag);
   ASSERT_TRUE(t2.has_value());

   EXPECT_EQ(t1.value(), t2.value());
}

TEST(digitalSignature, SignWithPublicKey)
{
   auto ds = DS::create(Alg::RSA, kRSAPublicKey2048, HAlg::SHA2_224);
   ASSERT_TRUE(ds.has_value());

   auto tag = ds->sign(kTestPlaintext);
   EXPECT_FALSE(tag.has_value());
   EXPECT_EQ(tag.error(), ErrorCode::PublicKeySignFailure);
}

TEST(digitalSignature, lowLevelOperationsAbuse)
{
   auto ds = DS::create(Alg::DSA, kDSAPrivateKey2048, HAlg::SHA1);
   ASSERT_TRUE(ds.has_value());

   // Errors from uninitialized state
   EXPECT_EQ(ds->signUpdate({}).error(), ErrorCode::SignUpdateNotAllowed);
   EXPECT_EQ(ds->signFinal().error(), ErrorCode::SignFinalNotAllowed);
   EXPECT_EQ(ds->verifyUpdate({}).error(), ErrorCode::VerifyUpdateNotAllowed);
   EXPECT_EQ(ds->verifyFinal({}).error(), ErrorCode::VerifyFinalNotAllowed);

   // Errors from sign initialized state
   auto sinit = ds->signInit();
   ASSERT_TRUE(sinit.has_value());

   EXPECT_EQ(ds->signFinal().error(), ErrorCode::SignFinalNotAllowed);
   EXPECT_EQ(ds->verifyUpdate({}).error(), ErrorCode::VerifyUpdateNotAllowed);
   EXPECT_EQ(ds->verifyFinal({}).error(), ErrorCode::VerifyFinalNotAllowed);

   // Errors from sign in progress state
   auto sup = ds->signUpdate(kTestPlaintext);
   ASSERT_TRUE(sup.has_value());
   EXPECT_EQ(ds->verifyUpdate({}).error(), ErrorCode::VerifyUpdateNotAllowed);
   EXPECT_EQ(ds->verifyFinal({}).error(), ErrorCode::VerifyFinalNotAllowed);

   // Errors from verify initialized state
   auto vinit = ds->verifyInit();
   ASSERT_TRUE(vinit.has_value());

   EXPECT_EQ(ds->verifyFinal({}).error(), ErrorCode::VerifyFinalNotAllowed);
   EXPECT_EQ(ds->signUpdate({}).error(), ErrorCode::SignUpdateNotAllowed);
   EXPECT_EQ(ds->signFinal().error(), ErrorCode::SignFinalNotAllowed);

   // Errors from verify in progress state
   auto vup = ds->verifyUpdate(kTestPlaintext);
   ASSERT_TRUE(vup.has_value());

   EXPECT_EQ(ds->signUpdate({}).error(), ErrorCode::SignUpdateNotAllowed);
   EXPECT_EQ(ds->signFinal().error(), ErrorCode::SignFinalNotAllowed);
}
