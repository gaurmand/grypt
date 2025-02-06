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
      case Alg::CHACHA20_POLY1305: return "ChaCha20-Poly1305";

      default: return {};
   }
}

} // namespace

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
      return std::unexpected(ErrorCode::FetchCipherFailed);
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
      return std::unexpected(ErrorCode::FetchCipherFailed);
   }
   return cipher;
}

std::expected<evp_cipher_ctx_ptr, Error> makeCipherContext()
{
   ossl::evp_cipher_ctx_ptr ctx{EVP_CIPHER_CTX_new()};
   if (!ctx)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::CreateCipherContextFailed};
   }

   return ctx;
}

std::expected<void, Error> resetCipherContext(evp_cipher_ctx_ptr& ctx)
{
   auto res = EVP_CIPHER_CTX_reset(ctx.get());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::ResetCipherContextFailed};
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
      return std::unexpected(ErrorCode::FetchCipherParamsFailed);
   }

   info.mode = toMode(modeNum);
   assert(info.keyLength > 0);
   assert(info.blockSize > 0);
   assert(info.ivLength >= 0);
   assert(info.mode != Mode::None);

   return info;
}

} // namespace grypt::ossl
