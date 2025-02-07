#include "testutil.h"

#include <grypt/algorithm.h>
#include <grypt/authsymmetriccipher.h>
#include <grypt/randombytes.h>
#include <gtest/gtest.h>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

using namespace grypt;
using namespace grypt::literals;

testing::AssertionResult roundTrip(AuthSymmetricCipherAlgorithm alg)
{
   auto cipher = AuthSymmetricCipher::create(kTestKey, alg);
   if (!cipher.has_value())
   {
      return testing::AssertionFailure() << "cipher creation failed";
   }

   auto enc = cipher->encrypt(kTestPlaintext, kTestIV1, kTestAAD);
   if (!enc.has_value())
   {
      return testing::AssertionFailure() << "encryption failed";
   }

   auto dec = cipher->decrypt(enc->ciphertext, kTestIV1, enc->tag, kTestAAD);
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

testing::AssertionResult authFailure(AuthSymmetricCipherAlgorithm alg,
                                     bool useAAD = false)
{
   Bytes aadBytes{kTestAAD};
   std::optional<BytesView> aad;
   if (useAAD)
   {
      aad = aadBytes;
   }

   auto cipher = AuthSymmetricCipher::create(kTestKey, alg);
   if (!cipher.has_value())
   {
      return testing::AssertionFailure() << "cipher creation failed";
   }

   auto enc = cipher->encrypt(kTestPlaintext, kTestIV1, aad);
   if (!enc.has_value())
   {
      return testing::AssertionFailure() << "encryption failed";
   }

   if (useAAD)
   {
      aadBytes.at(4) = std::byte{7};
   }
   else
   {
      enc->ciphertext.at(4) = std::byte{7};
   }

   auto dec = cipher->decrypt(enc->ciphertext, kTestIV1, enc->tag, aad);
   if (dec.has_value())
   {
      return testing::AssertionFailure() << "decryption succeeded";
   }

   return testing::AssertionSuccess();
}

TEST(authsymmetricKeyCipher, roundTrip)
{
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_128_GCM));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_128_OCB));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_128_CCM));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_128_SIV));

   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_192_GCM));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_192_OCB));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_192_CCM));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_192_SIV));

   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_256_GCM));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_256_OCB));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_256_CCM));
   EXPECT_TRUE(roundTrip(AuthSymmetricCipherAlgorithm::AES_256_SIV));
}

TEST(authsymmetricKeyCipher, authFailure)
{
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_GCM, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_OCB, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_CCM, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_SIV, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_GCM, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_OCB, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_CCM, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_128_SIV, true));

   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_GCM, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_OCB, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_CCM, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_SIV, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_GCM, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_OCB, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_CCM, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_192_SIV, true));

   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_GCM, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_OCB, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_CCM, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_SIV, false));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_GCM, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_OCB, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_CCM, true));
   EXPECT_TRUE(authFailure(AuthSymmetricCipherAlgorithm::AES_256_SIV, true));
}

TEST(authsymmetricKeyCipher, multipleOperationsWithSameCipher)
{
   auto c = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_256_OCB);
   ASSERT_TRUE(c.has_value());

   auto enc1 = c->encrypt(kTestPlaintext, kTestIV1, kTestAAD);
   ASSERT_TRUE(enc1.has_value());

   auto dec1 = c->decrypt(enc1->ciphertext, kTestIV1, enc1->tag, kTestAAD);
   ASSERT_TRUE(dec1.has_value());

   EXPECT_EQ(dec1.value(), kTestPlaintext);

   auto enc2 = c->encrypt(kTestPlaintext, kTestIV2);
   ASSERT_TRUE(enc2.has_value());

   auto dec2 = c->decrypt(enc2->ciphertext, kTestIV2, enc2->tag);
   ASSERT_TRUE(dec2.has_value());

   EXPECT_EQ(dec2.value(), kTestPlaintext);
   EXPECT_NE(enc1->ciphertext, enc2->ciphertext);
   EXPECT_NE(enc1->tag, enc2->tag);
}

TEST(authsymmetricKeyCipher, invalidKeyLength)
{
   auto c1 = AuthSymmetricCipher::create(
      Bytes(16), AuthSymmetricCipherAlgorithm::AES_256_CCM);
   ASSERT_FALSE(c1.has_value());
   ASSERT_EQ(c1.error(), ErrorCode::InvalidKeyLength);

   auto c2 = AuthSymmetricCipher::create(
      Bytes(8), AuthSymmetricCipherAlgorithm::AES_128_CCM);
   ASSERT_FALSE(c2.has_value());
   ASSERT_EQ(c2.error(), ErrorCode::InvalidKeyLength);
}

TEST(authsymmetricKeyCipher, invalidIVLength)
{
   auto c1 = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_256_GCM);
   ASSERT_TRUE(c1.has_value());

   auto enc1 = c1->encrypt(kTestPlaintext, Bytes(10));
   ASSERT_FALSE(enc1.has_value());
   ASSERT_EQ(enc1.error(), ErrorCode::InvalidIVLength);

   auto dec1 = c1->decrypt(kTestPlaintext, Bytes(10), Bytes{});
   ASSERT_FALSE(dec1.has_value());
   ASSERT_EQ(dec1.error(), ErrorCode::InvalidIVLength);

   auto c2 = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_192_GCM);
   ASSERT_TRUE(c2.has_value());

   auto enc2 = c2->encrypt(kTestPlaintext, Bytes(10));
   ASSERT_FALSE(enc2.has_value());
   ASSERT_EQ(enc2.error(), ErrorCode::InvalidIVLength);

   auto dec2 = c2->decrypt(kTestPlaintext, Bytes(10), Bytes{});
   ASSERT_FALSE(dec2.has_value());
   ASSERT_EQ(dec2.error(), ErrorCode::InvalidIVLength);
}

TEST(authsymmetricKeyCipher, SIVMode)
{
   // SIV uses the plaintext/AAD to generate an internal IV. The supplied IV is
   // ignored.
   auto c = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_128_SIV);
   ASSERT_TRUE(c.has_value());

   auto enc1 = c->encrypt(kTestPlaintext, Bytes());
   ASSERT_TRUE(enc1.has_value());

   auto enc2 = c->encrypt(kTestPlaintext, kTestIV1);
   ASSERT_TRUE(enc2.has_value());

   auto enc3 = c->encrypt(kTestPlaintext, Bytes(), kTestAAD);
   ASSERT_TRUE(enc3.has_value());

   EXPECT_EQ(enc1->ciphertext, enc2->ciphertext);
   EXPECT_NE(enc1->ciphertext, enc3->ciphertext);
}

TEST(authsymmetricKeyCipher, multiStepEncrypt)
{
   auto c = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_128_GCM);
   ASSERT_TRUE(c.has_value());

   auto init = c->encryptInit(kTestIV1);
   ASSERT_TRUE(init.has_value());

   const auto data = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto aad  = data | std::views::chunk(12);
   const auto pt   = data | std::views::chunk(12);

   auto aad1 = c->encryptAAD(BytesView{aad[0]});
   ASSERT_TRUE(aad1.has_value());
   auto aad2 = c->encryptAAD(BytesView{aad[1]});
   ASSERT_TRUE(aad2.has_value());
   auto aad3 = c->encryptAAD(BytesView{aad[2]});
   ASSERT_TRUE(aad3.has_value());

   Bytes enc;
   auto enc1 = c->encryptUpdate(BytesView{pt[0]});
   ASSERT_TRUE(enc1.has_value());
   enc += enc1.value();
   auto enc2 = c->encryptUpdate(BytesView{pt[1]});
   ASSERT_TRUE(enc2.has_value());
   enc += enc2.value();
   auto enc3 = c->encryptUpdate(BytesView{pt[2]});
   ASSERT_TRUE(enc3.has_value());
   enc += enc3.value();
   auto enc4 = c->encryptFinal();
   ASSERT_TRUE(enc4.has_value());
   enc += enc4->ciphertext;

   auto encSimple = c->encrypt(data, kTestIV1, data);
   ASSERT_TRUE(encSimple.has_value());
   std::cout << encSimple->ciphertext << "\n";
   std::cout << encSimple->tag << "\n";

   EXPECT_EQ(enc, encSimple->ciphertext);
   EXPECT_EQ(enc4->tag, enc4->tag);
}

TEST(authsymmetricKeyCipher, multiStepDecrypt)
{
   auto c = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_128_GCM);
   ASSERT_TRUE(c.has_value());

   const auto data = "aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc"_b;
   const auto aad  = data | std::views::chunk(12);

   const auto tag = Bytes::fromHex("0xceb3a8c260ed21a840cdbc0cae2fc35b");

   auto init = c->decryptInit(kTestIV1, tag);
   ASSERT_TRUE(init.has_value());

   const auto ciphertext =
      Bytes::fromHex("0x0f5cad68f82fa517befa26f2b3a4cd06cc9d6756f4fc28a09de41bc"
                     "9091ad7b9bb5097d5");
   const auto chunks = ciphertext | std::views::chunk(24);

   auto aad1 = c->decryptAAD(BytesView{aad[0]});
   ASSERT_TRUE(aad1.has_value());
   auto aad2 = c->decryptAAD(BytesView{aad[1]});
   ASSERT_TRUE(aad2.has_value());
   auto aad3 = c->decryptAAD(BytesView{aad[2]});
   ASSERT_TRUE(aad3.has_value());

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

   auto decSimple = c->decrypt(ciphertext, kTestIV1, tag, data);
   ASSERT_TRUE(decSimple.has_value());
   EXPECT_EQ(dec, decSimple.value());
}

TEST(authsymmetricKeyCipher, lowLevelOperationsAbuse)
{
   auto c = AuthSymmetricCipher::create(
      kTestKey, AuthSymmetricCipherAlgorithm::AES_128_GCM);
   ASSERT_TRUE(c.has_value());

   // Errors from uninitialized state
   EXPECT_EQ(c->encryptAAD({}).error(), ErrorCode::EncryptAADNotAllowed);
   EXPECT_EQ(c->encryptUpdate({}).error(), ErrorCode::EncryptUpdateNotAllowed);
   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);
   EXPECT_EQ(c->decryptAAD({}).error(), ErrorCode::DecryptAADNotAllowed);
   EXPECT_EQ(c->decryptUpdate({}).error(), ErrorCode::DecryptUpdateNotAllowed);
   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);

   // Errors from encryption initialized state
   auto einit = c->encryptInit(kTestIV1);
   ASSERT_TRUE(einit.has_value());

   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);
   EXPECT_EQ(c->decryptAAD({}).error(), ErrorCode::DecryptAADNotAllowed);
   EXPECT_EQ(c->decryptUpdate({}).error(), ErrorCode::DecryptUpdateNotAllowed);
   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);

   // Errors from encryption in progress state
   auto eup = c->encryptUpdate(kTestPlaintext);
   ASSERT_TRUE(eup.has_value());

   EXPECT_EQ(c->encryptAAD({}).error(), ErrorCode::EncryptAADNotAllowed);
   EXPECT_EQ(c->decryptAAD({}).error(), ErrorCode::DecryptAADNotAllowed);
   EXPECT_EQ(c->decryptUpdate({}).error(), ErrorCode::DecryptUpdateNotAllowed);
   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);

   // Errors from decryption initialized state
   auto dinit = c->decryptInit(kTestIV1, Bytes(16));
   ASSERT_TRUE(dinit.has_value());

   EXPECT_EQ(c->decryptFinal().error(), ErrorCode::DecryptFinalNotAllowed);
   EXPECT_EQ(c->encryptAAD({}).error(), ErrorCode::EncryptAADNotAllowed);
   EXPECT_EQ(c->encryptUpdate({}).error(), ErrorCode::EncryptUpdateNotAllowed);
   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);

   // Errors from decryption in progress state
   auto dup = c->decryptUpdate(kTestPlaintext);
   ASSERT_TRUE(dup.has_value());

   EXPECT_EQ(c->decryptAAD({}).error(), ErrorCode::DecryptAADNotAllowed);
   EXPECT_EQ(c->encryptAAD({}).error(), ErrorCode::EncryptAADNotAllowed);
   EXPECT_EQ(c->encryptUpdate({}).error(), ErrorCode::EncryptUpdateNotAllowed);
   EXPECT_EQ(c->encryptFinal().error(), ErrorCode::EncryptFinalNotAllowed);
}
