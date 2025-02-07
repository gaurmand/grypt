#include "testutil.h"

#include <grypt/algorithm.h>
#include <grypt/randombytes.h>
#include <grypt/symmetriccipher.h>
#include <gtest/gtest.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

using namespace grypt;
using namespace grypt::literals;

testing::AssertionResult roundTrip(
   SymmetricCipherAlgorithm alg,
   std::optional<BytesView> plaintext = std::nullopt)
{
   auto cipher = SymmetricCipher::create(kTestKey, alg);
   if (!cipher.has_value())
   {
      return testing::AssertionFailure() << "cipher creation failed";
   }

   auto enc = cipher->encrypt(plaintext.value_or(kTestPlaintext), kTestIV1);
   if (!enc.has_value())
   {
      return testing::AssertionFailure() << "encryption failed";
   }

   auto dec = cipher->decrypt(enc.value(), kTestIV1);
   if (!dec.has_value())
   {
      return testing::AssertionFailure() << "decryption failed";
   }

   if (dec.value() != plaintext.value_or(kTestPlaintext))
   {
      return testing::AssertionFailure() << "plaintext != recovered plaintext";
   }

   return testing::AssertionSuccess();
}

TEST(symmetricKeyCipher, roundTrip)
{
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_CBC));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_CBC_CTS));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_CFB));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_CFB1));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_CFB8));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_CTR));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_OFB));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_XTS));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_WRAP_PAD));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_128_WRAP_PAD_INV));

   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_CBC));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_CBC_CTS));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_CFB));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_CFB1));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_CFB8));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_CTR));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_OFB));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_WRAP_PAD));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_192_WRAP_PAD_INV));

   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_CBC));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_CBC_CTS));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_CFB));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_CFB1));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_CFB8));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_CTR));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_OFB));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_XTS));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_WRAP_PAD));
   EXPECT_TRUE(roundTrip(SymmetricCipherAlgorithm::AES_256_WRAP_PAD_INV));
}

TEST(symmetricKeyCipher, multipleOperationsWithSameCipher)
{
   auto c =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_256_OFB);
   ASSERT_TRUE(c.has_value());

   auto enc1 = c->encrypt(kTestPlaintext, kTestIV1);
   ASSERT_TRUE(enc1.has_value());

   auto dec1 = c->decrypt(enc1.value(), kTestIV1);
   ASSERT_TRUE(dec1.has_value());

   EXPECT_EQ(dec1.value(), kTestPlaintext);

   auto enc2 = c->encrypt(kTestPlaintext, kTestIV2);
   ASSERT_TRUE(enc2.has_value());

   auto dec2 = c->decrypt(enc2.value(), kTestIV2);
   ASSERT_TRUE(dec2.has_value());

   EXPECT_EQ(dec2.value(), kTestPlaintext);
   EXPECT_NE(enc1.value(), enc2.value());
}

TEST(symmetricKeyCipher, invalidKeyLength)
{
   auto c1 =
      SymmetricCipher::create(Bytes(16), SymmetricCipherAlgorithm::AES_256_CBC);
   ASSERT_FALSE(c1.has_value());
   ASSERT_EQ(c1.error(), ErrorCode::InvalidKeyLength);

   auto c2 =
      SymmetricCipher::create(Bytes(16), SymmetricCipherAlgorithm::AES_128_XTS);
   ASSERT_FALSE(c2.has_value());
   ASSERT_EQ(c2.error(), ErrorCode::InvalidKeyLength);
}

TEST(symmetricKeyCipher, invalidIVLength)
{
   auto c1 =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_256_CBC);
   ASSERT_TRUE(c1.has_value());

   auto enc1 = c1->encrypt(kTestPlaintext, Bytes(8));
   ASSERT_FALSE(enc1.has_value());
   ASSERT_EQ(enc1.error(), ErrorCode::InvalidIVLength);

   auto dec1 = c1->decrypt(kTestPlaintext, Bytes(8));
   ASSERT_FALSE(dec1.has_value());
   ASSERT_EQ(dec1.error(), ErrorCode::InvalidIVLength);

   auto c2 = SymmetricCipher::create(
      kTestKey, SymmetricCipherAlgorithm::AES_192_WRAP_PAD);
   ASSERT_TRUE(c2.has_value());

   auto enc2 = c2->encrypt(kTestPlaintext, Bytes(3));
   ASSERT_FALSE(enc2.has_value());
   ASSERT_EQ(enc2.error(), ErrorCode::InvalidIVLength);

   auto dec2 = c2->decrypt(kTestPlaintext, Bytes(3));
   ASSERT_FALSE(dec2.has_value());
   ASSERT_EQ(dec2.error(), ErrorCode::InvalidIVLength);
}

TEST(symmetricKeyCipher, ECBMode)
{
   // ECB doesn't use an IV, thus it produces the same output regardless of IV.
   auto c =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_128_ECB);
   ASSERT_TRUE(c.has_value());

   auto enc1 = c->encrypt(kTestPlaintext, Bytes());
   ASSERT_TRUE(enc1.has_value());

   auto enc2 = c->encrypt(kTestPlaintext, kTestIV1);
   ASSERT_TRUE(enc2.has_value());

   EXPECT_EQ(enc1, enc2);
}

TEST(symmetricKeyCipher, wrapModeInputSize)
{
   // Key wrap modes without padding require the input to be greater than 16 and
   // a multiple of 8.
   auto c1 =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_128_WRAP);
   ASSERT_TRUE(c1.has_value());

   auto enc1 = c1->encrypt(Bytes(15), kTestIV1);
   ASSERT_FALSE(enc1.has_value());
   auto enc2 = c1->encrypt(Bytes(16), kTestIV1);
   ASSERT_TRUE(enc2.has_value());

   auto c2 = SymmetricCipher::create(
      kTestKey, SymmetricCipherAlgorithm::AES_192_WRAP_INV);
   ASSERT_TRUE(c2.has_value());

   auto enc3 = c2->encrypt(Bytes(15), kTestIV1);
   ASSERT_FALSE(enc3.has_value());
   auto enc4 = c2->encrypt(Bytes(32), kTestIV1);
   ASSERT_TRUE(enc4.has_value());
}

TEST(symmetricKeyCipher, wrapModeAuthentication)
{
   // Key wrap modes are authenicated, i.e. decryption will fail if the
   // ciphertext was modified. Unlike other authenticated ciphers, key wrap
   // ciphers do not produce authentication tags or allow additional data to be
   // authenticated.
   auto c1 = SymmetricCipher::create(
      kTestKey, SymmetricCipherAlgorithm::AES_256_WRAP_PAD);
   ASSERT_TRUE(c1.has_value());

   auto enc1 = c1->encrypt(kTestPlaintext, kTestIV1);
   ASSERT_TRUE(enc1.has_value());

   auto dec1 = c1->decrypt(enc1.value(), kTestIV1);
   ASSERT_TRUE(dec1.has_value());

   enc1.value()[4] = std::byte{'a'};
   auto dec2       = c1->decrypt(enc1.value(), kTestIV1);
   ASSERT_FALSE(dec2.has_value());
}

TEST(symmetricKeyCipher, multiStepEncrypt)
{
   auto c =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_128_CBC);
   ASSERT_TRUE(c.has_value());

   auto init = c->encryptInit(kTestIV1);
   ASSERT_TRUE(init.has_value());

   const auto plaintext = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto chunks    = plaintext | std::views::chunk(12);

   Bytes enc;
   auto enc1 = c->encryptUpdate(BytesView{chunks[0]});
   ASSERT_TRUE(enc1.has_value());
   enc += enc1.value();
   auto enc2 = c->encryptUpdate(BytesView{chunks[1]});
   ASSERT_TRUE(enc2.has_value());
   enc += enc2.value();
   auto enc3 = c->encryptUpdate(BytesView{chunks[2]});
   ASSERT_TRUE(enc3.has_value());
   enc += enc3.value();
   auto enc4 = c->encryptFinal();
   ASSERT_TRUE(enc4.has_value());
   enc += enc4.value();

   auto encSimple = c->encrypt(plaintext, kTestIV1);
   ASSERT_TRUE(encSimple.has_value());
   EXPECT_EQ(enc, encSimple.value());
}

TEST(symmetricKeyCipher, multiStepDecrypt)
{
   auto c =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_128_CBC);
   ASSERT_TRUE(c.has_value());

   auto init = c->decryptInit(kTestIV1);
   ASSERT_TRUE(init.has_value());

   const auto ciphertext =
      Bytes::fromHex("0x144837ec931420312ce54b07176f826a853fb36b60cf5533468ed76"
                     "920c4a872c9969199c9ae643b19c1ae56db740644");
   const auto chunks = ciphertext | std::views::chunk(16);

   Bytes dec;
   auto dec1 = c->decryptUpdate(BytesView{chunks[0]});
   ASSERT_TRUE(dec1.has_value());
   dec += dec1.value();
   auto dec2 = c->decryptUpdate(BytesView{chunks[1]});
   ASSERT_TRUE(dec2.has_value());
   dec += dec2.value();
   auto dec3 = c->decryptUpdate(BytesView{chunks[2]});
   ASSERT_TRUE(dec3.has_value());
   dec += dec3.value();
   auto dec4 = c->decryptFinal();
   ASSERT_TRUE(dec4.has_value());
   dec += dec4.value();

   auto decSimple = c->decrypt(ciphertext, kTestIV1);
   ASSERT_TRUE(decSimple.has_value());
   EXPECT_EQ(dec, decSimple.value());
}

TEST(symmetricKeyCipher, lowLevelOperationsAbuse)
{
   auto c =
      SymmetricCipher::create(kTestKey, SymmetricCipherAlgorithm::AES_128_CFB);
   ASSERT_TRUE(c.has_value());

   // Errors from uninitialized state
   EXPECT_EQ(c->encryptUpdate({}).error(), ErrorCode::EncryptUpdateNotAllowed);
   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);
   EXPECT_EQ(c->decryptUpdate({}).error(), ErrorCode::DecryptUpdateNotAllowed);
   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);

   // Errors from encryption initialized state
   auto einit = c->encryptInit(kTestIV1);
   ASSERT_TRUE(einit.has_value());

   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);
   EXPECT_EQ(c->decryptUpdate({}).error(), ErrorCode::DecryptUpdateNotAllowed);
   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);

   // Errors from encryption in progress state
   auto eup = c->encryptUpdate(kTestPlaintext);
   ASSERT_TRUE(eup.has_value());

   EXPECT_EQ(c->decryptUpdate({}).error(), ErrorCode::DecryptUpdateNotAllowed);
   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);

   // Errors from decryption initialized state
   auto dinit = c->decryptInit(kTestIV1);
   ASSERT_TRUE(dinit.has_value());

   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);
   EXPECT_EQ(c->encryptUpdate({}).error(), ErrorCode::EncryptUpdateNotAllowed);
   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);

   // Errors from decryption in progress state
   auto dup = c->decryptUpdate(kTestPlaintext);
   ASSERT_TRUE(dup.has_value());

   EXPECT_EQ(c->encryptUpdate({}).error(), ErrorCode::EncryptUpdateNotAllowed);
   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);
}
