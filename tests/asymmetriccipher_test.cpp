#include "data.h"
#include "testutil.h"

#include <grypt/algorithm.h>
#include <grypt/asymmetriccipher.h>
#include <gtest/gtest.h>
#include <iostream>

using namespace grypt;
using namespace grypt::literals;

using Cipher = AsymmetricCipher;
using Alg    = AsymmetricCipher::Algorithm;
using Info   = AsymmetricCipher::AlgorithmInfo;

testing::AssertionResult roundTrip(Alg alg)
{
   auto cipher = Cipher::create(alg, kRSAPrivateKey4096);
   if (!cipher.has_value())
   {
      return testing::AssertionFailure() << "cipher creation failed";
   }

   auto enc = cipher->encrypt(kTestPlaintext);
   if (!enc.has_value())
   {
      return testing::AssertionFailure() << "encryption failed";
   }

   auto dec = cipher->decrypt(enc.value());
   if (!dec.has_value())
   {
      return testing::AssertionFailure() << "decryption failed";
   }

   if (dec.value() != kTestPlaintext)
   {
      return testing::AssertionFailure() << "plaintext != recovered plaintext";
   }

   return testing::AssertionSuccess();
}

TEST(asymmetricCipher, cipherCreation)
{
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, 64).has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, 256).has_value());
   ASSERT_TRUE(
      Cipher::create(Alg::RSA_NO_PAD, "data/rsa_priv.der").has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, "data/rsa_pub.der").has_value());
   ASSERT_TRUE(
      Cipher::create(Alg::RSA_NO_PAD, "data/rsa_priv.pem").has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, "data/rsa_pub.pem").has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, kRSAPrivateKey4096).has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, kRSAPublicKey4096).has_value());
}

TEST(asymmetricCipher, roundTrip)
{
   // EXPECT_TRUE(roundTrip(Alg::RSA_NO_PAD));
   EXPECT_TRUE(roundTrip(Alg::RSA_PKCS1));
   EXPECT_TRUE(roundTrip(Alg::RSA_PKCS1_OAEP_MGF1_SHA1));
   EXPECT_TRUE(roundTrip(Alg::RSA_PKCS1_OAEP_MGF1_SHA256));
   EXPECT_TRUE(roundTrip(Alg::RSA_PKCS1_OAEP_MGF1_SHA512));
}

TEST(asymmetricCipher, info)
{
   EXPECT_EQ(Cipher::create(Alg::RSA_NO_PAD, 64)->info(), Info(64, 64, true));
   EXPECT_EQ(Cipher::create(Alg::RSA_PKCS1, 128)->info(), Info(128, 117, true));
   EXPECT_EQ(Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA1, 256)->info(),
             Info(256, 215, true));
   EXPECT_EQ(Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA256, kRSAPrivateKey4096)
                ->info(),
             Info(512, 446, true));
   EXPECT_EQ(Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA512, kRSAPublicKey4096)
                ->info(),
             Info(512, 382, false));
}

TEST(asymmetricCipher, maxPlaintextLength)
{
   auto c1 = Cipher::create(Alg::RSA_PKCS1, 64);
   ASSERT_TRUE(c1.has_value());

   auto enc1 = c1->encrypt(Bytes(53));
   EXPECT_TRUE(enc1.has_value());

   auto enc2 = c1->encrypt(Bytes(54));
   EXPECT_FALSE(enc2.has_value());
   EXPECT_EQ(enc2.error(), ErrorCode::InvalidPlaintextLength);

   auto c2 =
      Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA256, kRSAPrivateKey4096);
   ASSERT_TRUE(c2.has_value());

   auto enc3 = c2->encrypt(Bytes(446));
   EXPECT_TRUE(enc3.has_value());

   auto enc4 = c2->encrypt(Bytes(447));
   EXPECT_FALSE(enc4.has_value());
   EXPECT_EQ(enc4.error(), ErrorCode::InvalidPlaintextLength);
}

TEST(asymmetricCipher, maxPlaintextLengthEdgeCase)
{
   // OAEP SHA-256 padding = 130 bytes of overhead, therefore a modulus of 64 is
   // too small to encrypt a plaintext of any size.
   auto c = Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA512, 64);
   ASSERT_TRUE(c.has_value());
   EXPECT_EQ(c->info().maxPlaintextLength, 0);

   auto enc = c->encrypt(kTestPlaintext);
   EXPECT_FALSE(enc.has_value());
}

TEST(asymmetricCipher, RSANoPadding)
{
   // Without padding, RSA requires the input and modulus size to be the same
   auto c = Cipher::create(Alg::RSA_NO_PAD, 64);
   ASSERT_TRUE(c.has_value());

   auto enc1 = c->encrypt(Bytes(64));
   EXPECT_TRUE(enc1.has_value());

   auto enc2 = c->encrypt(Bytes(65));
   EXPECT_FALSE(enc2.has_value());
   EXPECT_EQ(enc2.error(), ErrorCode::InvalidPlaintextLength);

   auto enc3 = c->encrypt(Bytes(63));
   EXPECT_FALSE(enc3.has_value());
   EXPECT_EQ(enc3.error(), ErrorCode::InvalidPlaintextLength);
}

TEST(asymmetricCipher, DecryptWithPublicKey)
{
   auto c = Cipher::create(Alg::RSA_PKCS1, kRSAPublicKey4096);
   ASSERT_TRUE(c.has_value());

   auto enc = c->encrypt(kTestPlaintext);
   EXPECT_TRUE(enc.has_value());

   auto dec = c->decrypt(enc.value());
   EXPECT_FALSE(dec.has_value());
   EXPECT_EQ(dec.error(), ErrorCode::PublicKeyDecryptFailure);
}
