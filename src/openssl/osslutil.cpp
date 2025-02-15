#include "osslutil.h"

#include <array>
#include <cassert>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

using namespace grypt;

namespace grypt::ossl
{

namespace
{

// Remove null characters from end of string.
void truncateString(std::string& str)
{
   str.erase(std::ranges::find(str, '\0'), str.end());
   str.shrink_to_fit();
}

Mode toMode(unsigned int modeNum)
{
   switch (modeNum)
   {
      case EVP_CIPH_CBC_MODE: return Mode::CBC;
      case EVP_CIPH_CCM_MODE: return Mode::CCM;
      case EVP_CIPH_CFB_MODE: return Mode::CFB;
      case EVP_CIPH_CTR_MODE: return Mode::CTR;
      case EVP_CIPH_ECB_MODE: return Mode::ECB;
      case EVP_CIPH_GCM_MODE: return Mode::GCM;
      case EVP_CIPH_OCB_MODE: return Mode::OCB;
      case EVP_CIPH_OFB_MODE: return Mode::OFB;
      case EVP_CIPH_SIV_MODE: return Mode::SIV;
      case EVP_CIPH_WRAP_MODE: return Mode::WRAP;
      case EVP_CIPH_XTS_MODE: return Mode::XTS;
      case EVP_CIPH_STREAM_CIPHER: return Mode::STREAM;
      default: return Mode::None;
   }
}

} // namespace

// Note: AES_128_CBC_HMAC_SHA1, AES_128_CBC_HMAC_SHA256, AES_256_CBC_HMAC_SHA1,
// AES_256_CBC_HMAC_SHA256 algorithms are supported but require additional
// operations to work correctly.
// Note: AES-XXX-GCM-SIV is supported only after OpenSSL 3.2.0
std::string_view toString(AuthSymmetricCipherAlgorithm alg)
{
   using Alg = AuthSymmetricCipherAlgorithm;

   switch (alg)
   {
      case Alg::AES_128_CCM: return "AES-128-CCM";
      case Alg::AES_128_GCM: return "AES-128-GCM";
      case Alg::AES_128_GCM_SIV: return "AES-128-GCM-SIV";
      case Alg::AES_128_OCB: return "AES-128-OCB";
      case Alg::AES_128_SIV: return "AES-128-SIV";

      case Alg::AES_192_CCM: return "AES-192-CCM";
      case Alg::AES_192_GCM: return "AES-192-GCM";
      case Alg::AES_192_GCM_SIV: return "AES-192-GCM-SIV";
      case Alg::AES_192_OCB: return "AES-192-OCB";
      case Alg::AES_192_SIV: return "AES-192-SIV";

      case Alg::AES_256_CCM: return "AES-256-CCM";
      case Alg::AES_256_GCM: return "AES-256-GCM";
      case Alg::AES_256_GCM_SIV: return "AES-256-GCM-SIV";
      case Alg::AES_256_OCB: return "AES-256-OCB";
      case Alg::AES_256_SIV: return "AES-256-SIV";

      case Alg::CHACHA20_POLY1305: return "ChaCha20-Poly1305";

      default: return {};
   }
}

std::string_view toString(SymmetricCipherAlgorithm alg)
{
   using Alg = SymmetricCipherAlgorithm;

   switch (alg)
   {
      case Alg::AES_128_CBC: return "AES-128-CBC";
      case Alg::AES_128_CBC_CTS: return "AES-128-CBC-CTS";
      case Alg::AES_128_CFB: return "AES-128-CFB";
      case Alg::AES_128_CFB1: return "AES-128-CFB1";
      case Alg::AES_128_CFB8: return "AES-128-CFB8";
      case Alg::AES_128_CTR: return "AES-128-CTR";
      case Alg::AES_128_ECB: return "AES-128-ECB";
      case Alg::AES_128_OFB: return "AES-128-OFB";
      case Alg::AES_128_XTS: return "AES-128-XTS";
      case Alg::AES_128_WRAP: return "AES-128-WRAP";
      case Alg::AES_128_WRAP_PAD: return "AES-128-WRAP-PAD";
      case Alg::AES_128_WRAP_INV: return "AES-128-WRAP-INV";
      case Alg::AES_128_WRAP_PAD_INV: return "AES-128-WRAP-PAD-INV";

      case Alg::AES_192_CBC: return "AES-192-CBC";
      case Alg::AES_192_CBC_CTS: return "AES-192-CBC-CTS";
      case Alg::AES_192_CFB: return "AES-192-CFB";
      case Alg::AES_192_CFB1: return "AES-192-CFB1";
      case Alg::AES_192_CFB8: return "AES-192-CFB8";
      case Alg::AES_192_CTR: return "AES-192-CTR";
      case Alg::AES_192_ECB: return "AES-192-ECB";
      case Alg::AES_192_OFB: return "AES-192-OFB";
      case Alg::AES_192_WRAP: return "AES-192-WRAP";
      case Alg::AES_192_WRAP_PAD: return "AES-192-WRAP-PAD";
      case Alg::AES_192_WRAP_INV: return "AES-192-WRAP-INV";
      case Alg::AES_192_WRAP_PAD_INV: return "AES-192-WRAP-PAD-INV";

      case Alg::AES_256_CBC: return "AES-256-CBC";
      case Alg::AES_256_CBC_CTS: return "AES-256-CBC-CTS";
      case Alg::AES_256_CFB: return "AES-256-CFB";
      case Alg::AES_256_CFB1: return "AES-256-CFB1";
      case Alg::AES_256_CFB8: return "AES-256-CFB8";
      case Alg::AES_256_CTR: return "AES-256-CTR";
      case Alg::AES_256_ECB: return "AES-256-ECB";
      case Alg::AES_256_OFB: return "AES-256-OFB";
      case Alg::AES_256_XTS: return "AES-256-XTS";
      case Alg::AES_256_WRAP: return "AES-256-WRAP";
      case Alg::AES_256_WRAP_PAD: return "AES-256-WRAP-PAD";
      case Alg::AES_256_WRAP_INV: return "AES-256-WRAP-INV";
      case Alg::AES_256_WRAP_PAD_INV: return "AES-256-WRAP-PAD-INV";

      case Alg::CHACHA20: return "ChaCha20";

      default: return {};
   }
}

std::string_view toString(HashAlgorithm alg)
{
   using Alg = HashAlgorithm;

   switch (alg)
   {
      case Alg::BLAKE2S_256: return "BLAKE2S-256";
      case Alg::BLAKE2B_512: return "BLAKE2B-512";

      case Alg::MD5: return "MD5";
      case Alg::MD5_SHA1: return "MD5-SHA1";

      case Alg::RIPEMD_160: return "RIPEMD-160";

      case Alg::SHA1: return "SHA1";

      case Alg::SHA2_224: return "SHA2-224";
      case Alg::SHA2_256: return "SHA2-256";
      case Alg::SHA2_384: return "SHA2-384";
      case Alg::SHA2_512: return "SHA2-512";
      case Alg::SHA2_512_224: return "SHA2-512/224";
      case Alg::SHA2_512_256: return "SHA2-512/256";

      case Alg::SHA3_224: return "SHA3-224";
      case Alg::SHA3_256: return "SHA3-256";
      case Alg::SHA3_384: return "SHA3-384";
      case Alg::SHA3_512: return "SHA3-512";

      case Alg::SHAKE_128: return "SHAKE-128";
      case Alg::SHAKE_256: return "SHAKE-256";
      case Alg::KECCAK_KMAC_128: return "KECCAK-KMAC-128";
      case Alg::KECCAK_KMAC_256: return "KECCAK-KMAC-256";

      case Alg::SM3: return "SM3";

      default: return {};
   }
}

std::string_view toString(MACAlgorithm alg)
{
   using Alg = MACAlgorithm;

   switch (alg)
   {
      case Alg::BLAKE2SMAC: return "BLAKE2SMAC";
      case Alg::BLAKE2BMAC: return "BLAKE2BMAC";
      case Alg::CMAC: return "CMAC";
      case Alg::GMAC: return "GMAC";
      case Alg::HMAC: return "HMAC";
      case Alg::KMAC_128: return "KMAC-128";
      case Alg::KMAC_256: return "KMAC-256";
      case Alg::SIPHASH: return "SIPHASH";
      // case Alg::Poly1305: return "POLY1305";
      default: return {};
   }
}

std::string_view toString(CMACAlgorithm alg)
{
   using Alg  = CMACAlgorithm;
   using SAlg = SymmetricCipherAlgorithm;

   switch (alg)
   {
      case Alg::AES_128_CBC: return toString(SAlg::AES_128_CBC);
      case Alg::AES_192_CBC: return toString(SAlg::AES_192_CBC);
      case Alg::AES_256_CBC: return toString(SAlg::AES_256_CBC);
      default: return {};
   }
}

std::string_view toString(GMACAlgorithm alg)
{
   using Alg  = GMACAlgorithm;
   using AAlg = AuthSymmetricCipherAlgorithm;

   switch (alg)
   {
      case Alg::AES_128_GCM: return toString(AAlg::AES_128_GCM);
      case Alg::AES_192_GCM: return toString(AAlg::AES_192_GCM);
      case Alg::AES_256_GCM: return toString(AAlg::AES_256_GCM);
      default: return {};
   }
}

std::string handleError()
{
   constexpr auto kBufferSize = 256;
   std::string msg(kBufferSize, '\0');

   if (auto ec = ERR_get_error(); ec != 0)
   {
      ERR_error_string_n(ec, msg.data(), kBufferSize);
   }
   truncateString(msg);

   if (msg.empty())
      msg = "Unknown OpenSSL error";

   std::cerr << msg << "\n";

   return msg;
}

std::expected<evp_cipher_ptr, Error> getCipher(SymmetricCipherAlgorithm alg)
{
   auto str = toString(alg);
   evp_cipher_ptr cipher{EVP_CIPHER_fetch(nullptr, str.data(), nullptr)};
   if (!cipher)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::InitializeCipherFailed);
   }
   return cipher;
}

std::expected<evp_cipher_ptr, Error> getCipher(AuthSymmetricCipherAlgorithm alg)
{
   auto str = toString(alg);
   evp_cipher_ptr cipher{EVP_CIPHER_fetch(nullptr, str.data(), nullptr)};
   if (!cipher)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::InitializeCipherFailed);
   }
   return cipher;
}

std::expected<evp_cipher_ctx_ptr, Error> makeCipherContext(
   const evp_cipher_ptr& cipher)
{
   ossl::evp_cipher_ctx_ptr ctx{EVP_CIPHER_CTX_new()};
   if (!ctx)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   auto res =
      EVP_EncryptInit_ex2(ctx.get(), cipher.get(), nullptr, nullptr, nullptr);
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   return ctx;
}

std::expected<void, Error> resetCipherContext(evp_cipher_ctx_ptr& ctx)
{
   auto res = EVP_CIPHER_CTX_reset(ctx.get());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   return {};
}

std::expected<AlgorithmInfo, Error> getInfo(const evp_cipher_ptr& cipher)
{
   AlgorithmInfo info;

   unsigned int modeNum{0};
   std::array<OSSL_PARAM, 5> params = {
      OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, &info.keyLength),
      OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &info.ivLength),
      OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE,
                                  &info.blockSize),
      OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_MODE, &modeNum),
      OSSL_PARAM_END};

   auto res = EVP_CIPHER_get_params(cipher.get(), params.data());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::FetchCipherDataFailed);
   }

   info.mode = toMode(modeNum);
   assert(info.keyLength > 0);
   assert(info.blockSize > 0);
   assert(info.ivLength >= 0);
   assert(info.mode != Mode::None);

   return info;
}

} // namespace grypt::ossl
