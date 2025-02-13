#include "testutil.h"

#include <grypt/algorithm.h>
#include <gtest/gtest.h>

using namespace grypt;
using SCA  = grypt::SymmetricCipherAlgorithm;
using Info = grypt::AlgorithmInfo;

TEST(algorithm, AES_256)
{
   // AES-256 uses 256 bit keys (XTS mode uses two keys => 512 bits).
   // Most modes use 128 bit IVs (ECB doesn't use an IV and authenticated modes
   // use different length IVs).
   // AES-256 uses a block size of 128 bits (WRAP modes use 64 bit blocks that
   // are concatenated before being input into the block cipher). A "block size"
   // of 1 means that the plaintext does not have to be padded to be a multiple
   // of the block size (i.e. effectively a stream cihper). This is is the case
   // for modes where the plaintext isn't directly used as an input to the block
   // cipher (e.g. CTR, CBC, OFB).

   // Non-authenticated modes
   EXPECT_EQ(getInfo(SCA::AES_256_ECB), Info(32, 0, 16, Mode::ECB));
   EXPECT_EQ(getInfo(SCA::AES_256_CBC), Info(32, 16, 16, Mode::CBC));
   EXPECT_EQ(getInfo(SCA::AES_256_CBC_CTS), Info(32, 16, 16, Mode::CBC));
   EXPECT_EQ(getInfo(SCA::AES_256_CFB), Info(32, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_256_CFB1), Info(32, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_256_CFB8), Info(32, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_256_OFB), Info(32, 16, 1, Mode::OFB));
   EXPECT_EQ(getInfo(SCA::AES_256_CTR), Info(32, 16, 1, Mode::CTR));
   EXPECT_EQ(getInfo(SCA::AES_256_XTS), Info(64, 16, 1, Mode::XTS));
   EXPECT_EQ(getInfo(SCA::AES_256_WRAP), Info(32, 8, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_256_WRAP_PAD), Info(32, 4, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_256_WRAP_INV), Info(32, 8, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_256_WRAP_PAD_INV), Info(32, 4, 8, Mode::WRAP));

   // Authenticated modes
   // EXPECT_EQ(getInfo(SCA::AES_256_CCM),
   //           Info(32, 12, 1, Mode::CCM));
   // EXPECT_EQ(getInfo(SCA::AES_256_GCM),
   //           Info(32, 12, 1, Mode::GCM));
   // EXPECT_EQ(getInfo(SCA::AES_256_GCM_SIV),
   //           Info(32, 12, 1, Mode::GCM));
   // EXPECT_EQ(getInfo(SCA::AES_256_OCB),
   //           Info(32, 12, 16, Mode::OCB));
   // EXPECT_EQ(getInfo(SCA::AES_256_SIV),
   //           Info(64, 0, 1, Mode::SIV));
}

TEST(algorithm, AES_128)
{
   // Non-authenticated modes
   EXPECT_EQ(getInfo(SCA::AES_128_ECB), Info(16, 0, 16, Mode::ECB));
   EXPECT_EQ(getInfo(SCA::AES_128_CBC), Info(16, 16, 16, Mode::CBC));
   EXPECT_EQ(getInfo(SCA::AES_128_CBC_CTS), Info(16, 16, 16, Mode::CBC));
   EXPECT_EQ(getInfo(SCA::AES_128_CFB), Info(16, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_128_CFB1), Info(16, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_128_CFB8), Info(16, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_128_OFB), Info(16, 16, 1, Mode::OFB));
   EXPECT_EQ(getInfo(SCA::AES_128_CTR), Info(16, 16, 1, Mode::CTR));
   EXPECT_EQ(getInfo(SCA::AES_128_XTS), Info(32, 16, 1, Mode::XTS));
   EXPECT_EQ(getInfo(SCA::AES_128_WRAP), Info(16, 8, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_128_WRAP_PAD), Info(16, 4, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_128_WRAP_INV), Info(16, 8, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_128_WRAP_PAD_INV), Info(16, 4, 8, Mode::WRAP));

   // Authenticated modes
   // EXPECT_EQ(getInfo(SCA::AES_128_CCM),
   //           Info(16, 12, 1, Mode::CCM));
   // EXPECT_EQ(getInfo(SCA::AES_128_GCM),
   //           Info(16, 12, 1, Mode::GCM));
   // EXPECT_EQ(getInfo(SCA::AES_128_GCM_SIV),
   //           Info(16, 12, 1, Mode::GCM));
   // EXPECT_EQ(getInfo(SCA::AES_128_OCB),
   //           Info(16, 12, 16, Mode::OCB));
   // EXPECT_EQ(getInfo(SCA::AES_128_SIV),
   //           Info(32, 0, 1, Mode::SIV));
}

TEST(algorithm, AES_192)
{
   // Non-authenticated modes
   EXPECT_EQ(getInfo(SCA::AES_192_ECB), Info(24, 0, 16, Mode::ECB));
   EXPECT_EQ(getInfo(SCA::AES_192_CBC), Info(24, 16, 16, Mode::CBC));
   EXPECT_EQ(getInfo(SCA::AES_192_CBC_CTS), Info(24, 16, 16, Mode::CBC));
   EXPECT_EQ(getInfo(SCA::AES_192_CFB), Info(24, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_192_CFB1), Info(24, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_192_CFB8), Info(24, 16, 1, Mode::CFB));
   EXPECT_EQ(getInfo(SCA::AES_192_OFB), Info(24, 16, 1, Mode::OFB));
   EXPECT_EQ(getInfo(SCA::AES_192_CTR), Info(24, 16, 1, Mode::CTR));
   EXPECT_EQ(getInfo(SCA::AES_192_WRAP), Info(24, 8, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_192_WRAP_PAD), Info(24, 4, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_192_WRAP_INV), Info(24, 8, 8, Mode::WRAP));
   EXPECT_EQ(getInfo(SCA::AES_192_WRAP_PAD_INV), Info(24, 4, 8, Mode::WRAP));

   // Authenticated modes
   // EXPECT_EQ(getInfo(SCA::AES_192_CCM),
   //           Info(24, 12, 1, Mode::CCM));
   // EXPECT_EQ(getInfo(SCA::AES_192_GCM),
   //           Info(24, 12, 1, Mode::GCM));
   // EXPECT_EQ(getInfo(SCA::AES_192_GCM_SIV),
   //           Info(24, 12, 1, Mode::GCM));
   // EXPECT_EQ(getInfo(SCA::AES_192_OCB),
   //           Info(24, 12, 16, Mode::OCB));
   // EXPECT_EQ(getInfo(SCA::AES_192_SIV),
   //           Info(48, 0, 1, Mode::SIV));
}

TEST(algorithm, ChaCha)
{
   EXPECT_EQ(getInfo(SCA::CHACHA20), Info(32, 16, 1, Mode::STREAM));
   // EXPECT_EQ(getInfo(SCA::CHACHA20_POLY1305), Info(32, 12, 1, Mode::STREAM));
}
