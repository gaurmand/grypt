#include "osslutil.h"
#include "pkey_util.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <grypt/algorithm.h>
#include <grypt/asymmetriccipher.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace grypt
{

namespace
{

std::expected<ossl::evp_pkey_ptr, Error> generateRSAKey(size_t sizeBits)
{
   ossl::evp_pkey_ptr pkey{EVP_RSA_gen(sizeBits)};
   if (pkey == nullptr)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::KeyGenerationFailure);
   }

   return pkey;
}

std::string_view getPaddingMode(AsymmetricCipher::Algorithm alg)
{
   switch (alg)
   {
      case AsymmetricCipher::Algorithm::RSA_NO_PAD:
         return OSSL_PKEY_RSA_PAD_MODE_NONE;
      case AsymmetricCipher::Algorithm::RSA_PKCS1:
         return OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA1:
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA256:
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA512:
      default: return OSSL_PKEY_RSA_PAD_MODE_OAEP;
   }
}

std::optional<std::string_view> getOEAPDigest(AsymmetricCipher::Algorithm alg)
{
   switch (alg)
   {
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA1: return "SHA1";
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA256:
         return "SHA256";
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA512:
         return "SHA512";
      default: return std::nullopt;
   }
}

auto getRSAParameters(AsymmetricCipher::Algorithm alg)
{
   std::array<OSSL_PARAM, 4> params = {
      OSSL_PARAM_construct_utf8_string(
         OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
         const_cast<char*>(getPaddingMode(alg).data()),
         0),
      OSSL_PARAM_END,
      OSSL_PARAM_END,
      OSSL_PARAM_END};

   auto digest = getOEAPDigest(alg);
   if (digest.has_value())
   {
      params[1] =
         OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                          const_cast<char*>(digest->data()),
                                          0);
      params[2] =
         OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                          const_cast<char*>(digest->data()),
                                          0);
   }

   return params;
}

std::expected<AsymmetricCipher::AlgorithmInfo, Error> getInfo(
   const ossl::evp_pkey_ptr& pkey,
   const ossl::evp_pkey_ctx_ptr& ctx,
   AsymmetricCipher::Algorithm alg)
{
   AsymmetricCipher::AlgorithmInfo info;

   std::array<OSSL_PARAM, 2> params = {
      OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_MAX_SIZE, &info.keyLength),
      OSSL_PARAM_END};

   auto res = EVP_PKEY_get_params(pkey.get(), params.data());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::FetchCipherDataFailed);
   }

   assert(info.keyLength > 0);

   long max{0};

   // https://docs.openssl.org/master/man3/RSA_public_encrypt/#description
   // https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep
   switch (alg)
   {
      case AsymmetricCipher::Algorithm::RSA_NO_PAD: max = info.keyLength; break;
      case AsymmetricCipher::Algorithm::RSA_PKCS1:
         max = info.keyLength - 11;
         break;
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA1:
         max = info.keyLength - 41;
         break;
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA256:
         max = info.keyLength - 66;
         break;
      case AsymmetricCipher::Algorithm::RSA_PKCS1_OAEP_MGF1_SHA512:
         max = info.keyLength - 130;
         break;
      default: return std::unexpected(ErrorCode::FetchCipherDataFailed);
   }

   info.maxPlaintextLength = std::max(max, 0l);

   info.isPrivateKey = EVP_PKEY_private_check(ctx.get()) == ERR_LIB_NONE;

   return info;
}

} // namespace

struct AsymmetricCipher::Data
{
   const Algorithm alg;
   const AlgorithmInfo info;
   ossl::evp_pkey_ptr pkey;
   ossl::evp_pkey_ctx_ptr ctx;

   bool isInvalidLen(size_t ptlen)
   {
      if (alg == Algorithm::RSA_NO_PAD)
      {
         return ptlen != info.keyLength;
      }
      else
      {
         return ptlen > info.maxPlaintextLength;
      }
   }

   std::expected<Bytes, Error> encrypt(BytesView plaintext)
   {
      if (isInvalidLen(plaintext.size()))
      {
         return std::unexpected(ErrorCode::InvalidPlaintextLength);
      }

      auto params = getRSAParameters(alg);
      auto res    = EVP_PKEY_encrypt_init_ex(ctx.get(), params.data());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::EncryptionFailure);
      }

      size_t len{0};
      res = EVP_PKEY_encrypt(
         ctx.get(), nullptr, &len, plaintext.udata(), plaintext.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::EncryptionFailure);
      }

      Bytes ciphertext(len);
      res = EVP_PKEY_encrypt(ctx.get(),
                             ciphertext.udata(),
                             &len,
                             plaintext.udata(),
                             plaintext.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::EncryptionFailure);
      }

      // std::cout << "encrypt inlen: " << plaintext.size() << "\n";
      // std::cout << "encrypt expected outlen: " << ciphertext.size() << "\n";
      // std::cout << "encrypt outlen: " << len << "\n";
      assert(static_cast<size_t>(len) <= ciphertext.size());
      ciphertext.resize(len);

      return ciphertext;
   }

   std::expected<Bytes, Error> decrypt(BytesView ciphertext)
   {
      if (!info.isPrivateKey)
      {
         return std::unexpected(ErrorCode::PublicKeyDecryptFailure);
      }

      auto params = getRSAParameters(alg);
      auto res    = EVP_PKEY_decrypt_init_ex(ctx.get(), params.data());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::EncryptionFailure);
      }

      size_t len{0};
      res = EVP_PKEY_decrypt(
         ctx.get(), nullptr, &len, ciphertext.udata(), ciphertext.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::EncryptionFailure);
      }

      Bytes plaintext(len);
      res = EVP_PKEY_decrypt(ctx.get(),
                             plaintext.udata(),
                             &len,
                             ciphertext.udata(),
                             ciphertext.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::EncryptionFailure);
      }

      // std::cout << "decrypt inlen: " << ciphertext.size() << "\n";
      // std::cout << "decrypt expected outlen: " << plaintext.size() << "\n";
      // std::cout << "decrypt outlen: " << len << "\n";
      assert(static_cast<size_t>(len) <= plaintext.size());
      plaintext.resize(len);

      return plaintext;
   }
};

std::expected<AsymmetricCipher, Error> AsymmetricCipher::create(
   Algorithm alg, size_t keyLength)
{
   auto pkey = generateRSAKey(keyLength * 8);
   if (!pkey.has_value())
   {
      return std::unexpected(pkey.error());
   }

   auto ctx = ossl::makeContext(pkey.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(pkey.value(), ctx.value(), alg);
   if (!info.has_value())
   {
      return std::unexpected(info.error());
   }

   AsymmetricCipher res;
   res.d_ = std::make_unique<AsymmetricCipher::Data>(alg,
                                                     std::move(info.value()),
                                                     std::move(pkey.value()),
                                                     std::move(ctx.value()));

   return res;
}

std::expected<AsymmetricCipher, Error> AsymmetricCipher::create(
   Algorithm alg, BytesView keyData)
{
   auto pkey = ossl::makePKeyFromData("RSA", keyData);
   if (!pkey.has_value())
   {
      return std::unexpected(pkey.error());
   }

   auto ctx = ossl::makeContext(pkey.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(pkey.value(), ctx.value(), alg);
   if (!info.has_value())
   {
      return std::unexpected(info.error());
   }

   AsymmetricCipher res;
   res.d_ = std::make_unique<AsymmetricCipher::Data>(alg,
                                                     std::move(info.value()),
                                                     std::move(pkey.value()),
                                                     std::move(ctx.value()));

   return res;
}

std::expected<AsymmetricCipher, Error> AsymmetricCipher::create(
   Algorithm alg, const std::filesystem::path& keyFilepath)
{
   auto pkey = ossl::makePKeyFromFile("RSA", keyFilepath);
   if (!pkey.has_value())
   {
      return std::unexpected(pkey.error());
   }

   auto ctx = makeContext(pkey.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(pkey.value(), ctx.value(), alg);
   if (!info.has_value())
   {
      return std::unexpected(info.error());
   }

   AsymmetricCipher res;
   res.d_ = std::make_unique<AsymmetricCipher::Data>(alg,
                                                     std::move(info.value()),
                                                     std::move(pkey.value()),
                                                     std::move(ctx.value()));

   return res;
}

std::expected<Bytes, Error> AsymmetricCipher::encrypt(BytesView plaintext)
{
   return d_->encrypt(plaintext);
}

std::expected<Bytes, Error> AsymmetricCipher::decrypt(BytesView ciphertext)
{
   return d_->decrypt(ciphertext);
}

AsymmetricCipher::Algorithm AsymmetricCipher::algorithm() const
{
   return d_->alg;
}

AsymmetricCipher::AlgorithmInfo AsymmetricCipher::info() const
{
   return d_->info;
}

AsymmetricCipher::~AsymmetricCipher() = default;

} // namespace grypt
