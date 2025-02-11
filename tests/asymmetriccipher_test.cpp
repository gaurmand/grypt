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

namespace
{

const auto kRSAPublicKey512 = Bytes::fromHex(
   "30820222300d06092a864886f70d01010105000382020f003082020a0282020100c97056b89"
   "fc0450055ad4e280dc9281decda47c0bf136bc2bdeb72e75b8eb65740b56abbb5c753f695ce"
   "c9a2f032da8f6a7d86339b50552e4077a43535627542830ed775956193ab900c1157ade13af"
   "887a1e2d5c5d832d31df8210ee5e52db659ab27de369470bc29fdb2f28663b854178b85658c"
   "eb79dab01734868e82508e0ec743b0e9dc8fed7c2420d4298be7b8b6704c08fe754ede1d5d3"
   "3541094e6e9e91a33f539bcdf552a23ae0f1feac47430e8bded0847b445fe756eaaffa2f82f"
   "bc972ef9f6f806ded1b053d89537b5e93d9bfcb9230ef9b33291b4ecc359ae2b8ef01c84310"
   "1e7c120369f2868f235d02cabf2d21f82c041ae85f46eb2eb2eb37a9f24a22e706faffde1d1"
   "82334244cf56af77608a2bcd4622274845c148f7b925e3aff2addae20303b683341a05f60c5"
   "d9ba41381458cd3209a5c377ea6c26d45487265ade632e08942ea4384c8541fd0fa250dff4d"
   "cdd749f94b0c5a76a25567f69caa37237928b9f552380271461e7597f39f83b5f89ebb097ca"
   "2511d0a367fb1822cee55ce07927745e4a50256a3ea2dbffefd53485eb6d7e55f17a4f6cbc8"
   "11c912be25cdcc922feff3a2364e7ef8f2482b60c198975aa0dffbca941d56fb24f783a34c9"
   "c1ff5dcdd8e0a663f3ac456a469dd4dec75f878e30af7e61eabbe40ef0a6f62ca58ed7be38a"
   "c8ae8cf17e8a3dbab9e3fab9688ff80f28d51a990203010001");

const auto kRSAPrivateKey512 = Bytes::fromHex(
   "308209280201000282020100c97056b89fc0450055ad4e280dc9281decda47c0bf136bc2bde"
   "b72e75b8eb65740b56abbb5c753f695cec9a2f032da8f6a7d86339b50552e4077a435356275"
   "42830ed775956193ab900c1157ade13af887a1e2d5c5d832d31df8210ee5e52db659ab27de3"
   "69470bc29fdb2f28663b854178b85658ceb79dab01734868e82508e0ec743b0e9dc8fed7c24"
   "20d4298be7b8b6704c08fe754ede1d5d33541094e6e9e91a33f539bcdf552a23ae0f1feac47"
   "430e8bded0847b445fe756eaaffa2f82fbc972ef9f6f806ded1b053d89537b5e93d9bfcb923"
   "0ef9b33291b4ecc359ae2b8ef01c843101e7c120369f2868f235d02cabf2d21f82c041ae85f"
   "46eb2eb2eb37a9f24a22e706faffde1d182334244cf56af77608a2bcd4622274845c148f7b9"
   "25e3aff2addae20303b683341a05f60c5d9ba41381458cd3209a5c377ea6c26d45487265ade"
   "632e08942ea4384c8541fd0fa250dff4dcdd749f94b0c5a76a25567f69caa37237928b9f552"
   "380271461e7597f39f83b5f89ebb097ca2511d0a367fb1822cee55ce07927745e4a50256a3e"
   "a2dbffefd53485eb6d7e55f17a4f6cbc811c912be25cdcc922feff3a2364e7ef8f2482b60c1"
   "98975aa0dffbca941d56fb24f783a34c9c1ff5dcdd8e0a663f3ac456a469dd4dec75f878e30"
   "af7e61eabbe40ef0a6f62ca58ed7be38ac8ae8cf17e8a3dbab9e3fab9688ff80f28d51a9902"
   "0301000102820200115dd92a2862ad083cfab8a1e123622d274bffd2e51e4d6470177e13e66"
   "bb8ba6fc29c41b3e7ac0c56a8c9ef3d5e6303a98a8a21059f40c2c0add7e73af3a2b8a1e02c"
   "10eff8a640aca5efb25394370f717112637bffba4d0378ce8fd05fe8679fd62ed51c77427b6"
   "472e20440f414b2924795eff5fce0a7eb15cb125d33acb27ca16f0b6ff4132806337ead8fe9"
   "e707c099d0a2575ec1768a894c192fa748bbaa9c36d5c9dd27d379b33308cc8782d9a21454b"
   "87c65e32bc426f76c30672a56c23f75fe38adb438ee52d17dbb0a9f292d45b71d76816e6365"
   "c5145833b4d5fc5d21c4119d00852c9c247d67005a3e6bb4c83bc2641353942e11d02ba18af"
   "f5ef445898f96092551f97bf71097552fe8dfe82ce15a7703f6933f1dac2c1171c92f00aed1"
   "a5d1d27be9aff425965610264ce0f6fcd0221392c6af5a8a1259f6be991dcaf2ae29800280a"
   "ebf53e20535a03746dcad25d0615512cb887e6a12c43df9d68f8bc2621f94108f549c3f59cd"
   "bff3c6d658c92e948527a8f7f5a3f24f0302ad741d15c81a731768d8fcf96e30bd0aab3d536"
   "2ffcde4271b9ed3558d2c34106f859ca23e0189cafaeae8e34acfcba5f56ffdb2bdd92b3f20"
   "8300185fd754981b7f130d5db2c0269f9ab5629496a97413c9c348d78c31cf3e398bd00837c"
   "faf6f0a227bbc5dbff467f1c099f8e1f4d344f39ee8249668d89b6001ed45c0810282010100"
   "faff61d9aa5ca88045bd887f59db4c7ba836c182140f05600d67480d0502e7b629e1cb8157e"
   "a8c0266d60ac5531b904303891e9f70febfe302eefdd797688369c47c1590bb771a07ef77b2"
   "49842614a186f4b01e39007d27635784d082bbd4952ee10b07a1a767b994b5d52093ace49a2"
   "6e125a364a1ae83a0dbdd14940cf1a9c6d41bc04e14c311797fa84a621c67b263fae437045a"
   "f7bff2d9dbea380740caf7f79e762e676f6f35af30c0f0efbff6fd8c69256c1bab857cf369d"
   "b7e3ba232cbea30a9ba747567b037238f314427d917f171578a9699f13f8fade1c1c7da0909"
   "14ff351485f94098eb8f4f67985883a5bf4843ebac47c47cf0c90d8c9b69190282010100cd7"
   "41a27d2fa4240341bf2383e9a89911f70e04106b5b946e401926a0821d846af6b4584c8aae4"
   "688df9ef90840b6099659d334d3d67459a0ea7aecd0e96257aba5fa71987327017f643664c8"
   "15722f24fee3a13109cdbff1f8493a79401f260ae2340704cd379de30e14e859e9f44bd66a4"
   "162681a4a5303c7d02939dad747bd03a91e9cd410ca100b67d2cddf89f09622a5d0634d3534"
   "741ea6325b0d42d7005c5acc26f548990797389e8222b96a33944cf35c4bb680ce599bf1181"
   "43715cfe3db8211bf8352283f257036da23c7132a3ca17f707b89534c892803d8201610fad4"
   "d2f7398bc42d9e68fb57b55216b16fbc5cccfeda0d32d0c86803221ed81028201005fc9e4da"
   "ffe43abe315f62df4f389d18b81aa580f20cc57d61c01fc4303c6a979fa63757166941a38d0"
   "174bcd7b9b6358cfce07df2ce960699d101792ca44b3aab2cbbc22f7905ab2f9d9ba1e8d7eb"
   "99b57a5e583a62d0609ece00b6de9db64474ce97ba02dc737e649d7c47e173e30e5d76213a1"
   "92687065ef66989f7f274abd9608b72b999bcd4476d0b99cf958d918c0c6cd9fe4485367104"
   "e9a39a5c5242e39d519142a660e5ad343dc3f46f5af074d5082faaf168651a497f05b0482bd"
   "f7ce8d447820bfdde6366b7a06729de974046f97d723b8566875e5afac44c740e6cb3e1adad"
   "366fe85233dbce6ef7ba180bc2535ef06b203c817e170c9fb393c90282010100cd69ab4cedc"
   "f70b5a863d8850b728ee01dc349333a762e4c0662dbf44f35277b649fa7ddde939dd23b410c"
   "983cacf363eb0884e650e213e0b78e47629596e0da17c4d2d8df273a937a906093552dbdaee"
   "ee38c04cbb348f1869d92d31553ecf564a5b223956c4a882feed4071c54b8f174d1d1a3a632"
   "eb4592f499c2e4ff2b5b2f11a0195632176251c822d6dd075a5a935f2faaa8de30812a12221"
   "6e8f8fa84ea007d7dd8b978e08dcd4ab060999bfe8d9f925c7bd9b36a5194aa47e229800a2d"
   "d79f64db060a79fbda2bcd2dabeb2a722af83f85a89e8fef3a29df359fe9a915777b9859c6f"
   "7530f714975755de40fa1e710187a3b67743bb22e37b5e7de0102820100311a928468424e4c"
   "401659051ff12076a9cd61acf60032e91f61ded9733ffe7d806c175c2296da614670db3ecfd"
   "8f845a3d1f281afcd40bcfebaa0462c4dfdfbe5a0f4572a919d3cd4727af2638933b5ae6638"
   "8a82f3d66644fb8a6696e3ce77cea481a702801c8a464d0544b3cff77415c20c33fe87f4773"
   "85ee58bb74532c9963cdbbe546a6a33ad9ffc4e61236e857d7207fd7715bd44cd17acc19aec"
   "4ed458f81e38a590de13c72b7f6bb5b3458c32e9f7bf0ab4974ed216203a7637bd6d3ec5ab7"
   "47057859caa5afd529630a367ce9c9337716acb972d82bc350348fc557175dbcfb04351b728"
   "ff28558d62d0d4735d8585227970954fcd69431480c858");

} // namespace

testing::AssertionResult roundTrip(Alg alg)
{
   auto cipher = Cipher::create(alg, kRSAPrivateKey512);
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
      Cipher::create(Alg::RSA_NO_PAD, "testdata/priv.der").has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, "testdata/pub.der").has_value());
   ASSERT_TRUE(
      Cipher::create(Alg::RSA_NO_PAD, "testdata/priv.pem").has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, "testdata/pub.pem").has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, kRSAPrivateKey512).has_value());
   ASSERT_TRUE(Cipher::create(Alg::RSA_NO_PAD, kRSAPublicKey512).has_value());
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
   EXPECT_EQ(Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA256, kRSAPrivateKey512)
                ->info(),
             Info(512, 446, true));
   EXPECT_EQ(
      Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA512, kRSAPublicKey512)->info(),
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

   auto c2 = Cipher::create(Alg::RSA_PKCS1_OAEP_MGF1_SHA256, kRSAPrivateKey512);
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
   auto c = Cipher::create(Alg::RSA_PKCS1, kRSAPublicKey512);
   ASSERT_TRUE(c.has_value());

   auto enc = c->encrypt(kTestPlaintext);
   EXPECT_TRUE(enc.has_value());

   auto dec = c->decrypt(enc.value());
   EXPECT_FALSE(dec.has_value());
   EXPECT_EQ(dec.error(), ErrorCode::PublicKeyDecryptFailure);
}
