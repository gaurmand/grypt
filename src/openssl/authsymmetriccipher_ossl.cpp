#include "osslutil.h"

#include <cassert>
#include <grypt/algorithm.h>
#include <grypt/authsymmetriccipher.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace grypt
{

namespace
{

std::expected<size_t, Error> getTagLength(AuthSymmetricCipherAlgorithm alg,
                                          const ossl::evp_cipher_ctx_ptr& ctx)
{
   // For some reason the taglen parameter for CHACHA20_POLY1305 is set to 0,
   // hardcode the proper value here as a workaround.
   if (alg == AuthSymmetricCipherAlgorithm::CHACHA20_POLY1305)
   {
      return EVP_CHACHAPOLY_TLS_TAG_LEN;
   }

   size_t taglen{0};
   std::array<OSSL_PARAM, 2> params = {
      OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen),
      OSSL_PARAM_END};

   auto res = EVP_CIPHER_CTX_get_params(ctx.get(), params.data());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::FetchCipherDataFailed);
   }

   assert(taglen != 0);

   return taglen;
}

std::expected<grypt::Bytes, Error> getTag(const ossl::evp_cipher_ctx_ptr& ctx,
                                          size_t tagLength)
{

   Bytes tag(tagLength);
   std::array<OSSL_PARAM, 2> params = {
      OSSL_PARAM_construct_octet_string(
         OSSL_CIPHER_PARAM_AEAD_TAG, tag.udata(), tag.size()),
      OSSL_PARAM_END};

   auto res = EVP_CIPHER_CTX_get_params(ctx.get(), params.data());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::FetchCipherDataFailed);
   }

   return tag;
}

} // namespace

struct AuthSymmetricCipher::Data
{
   enum class State
   {
      Uninitialized,
      EncryptionInitialized,
      DecryptionInitialized,
      EncryptionInProgress,
      DecryptionInProgress
   };

   const AuthSymmetricCipherAlgorithm alg;
   const Bytes key;
   const AlgorithmInfo info;
   const size_t tagLength;
   ossl::evp_cipher_ptr cipher;
   ossl::evp_cipher_ctx_ptr ctx;
   State state{State::Uninitialized};

   std::expected<void, Error> encryptInit(BytesView iv)
   {
      if (iv.size() < info.ivLength)
      {
         return std::unexpected{ErrorCode::InvalidIVLength};
      }

      auto res = EVP_EncryptInit_ex2(
         ctx.get(), nullptr, key.udata(), iv.udata(), nullptr);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::EncryptionFailure};
      }

      state = State::EncryptionInitialized;

      return {};
   }

   std::expected<void, Error> encryptAAD(
      BytesView aad, std::optional<size_t> ptlen = std::nullopt)
   {
      if (state != State::EncryptionInitialized)
      {
         return std::unexpected(ErrorCode::EncryptAADNotAllowed);
      }

      if (ptlen.has_value())
      {
         int len = 0;
         auto res =
            EVP_EncryptUpdate(ctx.get(), nullptr, &len, nullptr, ptlen.value());
         if (res != ERR_LIB_NONE)
         {
            ossl::handleError();
            return std::unexpected{ErrorCode::EncryptionFailure};
         }
      }

      // Set AAD
      int len = 0;
      auto res =
         EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.udata(), aad.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::EncryptionFailure};
      }

      assert(static_cast<size_t>(len) == aad.size());

      state = State::EncryptionInitialized;

      return {};
   }

   std::expected<Bytes, Error> encryptUpdate(BytesView plaintext)
   {
      if (state != State::EncryptionInitialized &&
          state != State::EncryptionInProgress)
      {
         return std::unexpected(ErrorCode::EncryptUpdateNotAllowed);
      }

      Bytes ciphertext(plaintext.size() + 2 * info.blockSize);

      int len  = 0;
      auto res = EVP_EncryptUpdate(ctx.get(),
                                   ciphertext.udata(),
                                   &len,
                                   plaintext.udata(),
                                   plaintext.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::EncryptionFailure};
      }

      // std::cout << "encrypt update inlen: " << plaintext.size() << "\n";
      // std::cout << "encrypt update expected outlen: " << ciphertext.size()
      //           << "\n";
      // std::cout << "encrypt update outlen: " << len << "\n";

      assert(static_cast<size_t>(len) <= ciphertext.size());
      ciphertext.resize(len);

      state = State::EncryptionInProgress;

      return ciphertext;
   }

   std::expected<EncryptionResult, Error> encryptFinal()
   {
      if (state != State::EncryptionInProgress)
      {
         return std::unexpected(ErrorCode::EncryptFinalNotAllowed);
      }

      Bytes ciphertext(info.blockSize);

      int len  = 0;
      auto res = EVP_EncryptFinal_ex(ctx.get(), ciphertext.udata(), &len);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::EncryptionFailure};
      }

      // std::cout << "encrypt final expected outlen: " << alg.blockSize <<
      // "\n"; std::cout << "encrypt final outlen: " << len << "\n";

      assert(static_cast<size_t>(len) <= ciphertext.size());
      ciphertext.resize(len);

      // Get generated authentication tag
      auto tag = getTag(ctx, tagLength);
      if (!tag.has_value())
      {
         return std::unexpected(tag.error());
      }

      state = State::Uninitialized;

      return EncryptionResult{std::move(ciphertext), std::move(tag.value())};
   }

   std::expected<void, Error> decryptInit(BytesView iv, BytesView tag)
   {
      if (iv.size() < info.ivLength)
      {
         return std::unexpected{ErrorCode::InvalidIVLength};
      }

      if (tag.size() < tagLength)
      {
         return std::unexpected{ErrorCode::InvalidTagLength};
      }

      // Sets expected authentication tag
      std::array<OSSL_PARAM, 2> params = {
         OSSL_PARAM_construct_octet_string(
            OSSL_CIPHER_PARAM_AEAD_TAG,
            const_cast<unsigned char*>(tag.udata()),
            tag.size()),
         OSSL_PARAM_END};

      auto res = EVP_DecryptInit_ex2(
         ctx.get(), nullptr, key.udata(), iv.udata(), params.data());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DecryptionFailure};
      }

      state = State::DecryptionInitialized;

      return {};
   }

   std::expected<void, Error> decryptAAD(
      BytesView aad, std::optional<size_t> ctlen = std::nullopt)
   {
      if (state != State::DecryptionInitialized)
      {
         return std::unexpected(ErrorCode::DecryptAADNotAllowed);
      }

      // Set ciphertext length
      if (ctlen.has_value())
      {
         int len = 0;
         auto res =
            EVP_DecryptUpdate(ctx.get(), nullptr, &len, nullptr, ctlen.value());
         if (res != ERR_LIB_NONE)
         {
            ossl::handleError();
            return std::unexpected{ErrorCode::DecryptionFailure};
         }
      }

      // Set AAD
      int len = 0;
      auto res =
         EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.udata(), aad.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DecryptionFailure};
      }

      assert(static_cast<size_t>(len) == aad.size());

      state = State::DecryptionInitialized;

      return {};
   }

   std::expected<Bytes, Error> decryptUpdate(BytesView ciphertext)
   {
      if (state != State::DecryptionInitialized &&
          state != State::DecryptionInProgress)
      {
         return std::unexpected(ErrorCode::DecryptUpdateNotAllowed);
      }

      Bytes plaintext(ciphertext.size() + 2 * info.blockSize);

      int len  = 0;
      auto res = EVP_DecryptUpdate(ctx.get(),
                                   plaintext.udata(),
                                   &len,
                                   ciphertext.udata(),
                                   ciphertext.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DecryptionFailure};
      }

      // std::cout << "decrypt update inlen: " << ciphertext.size() << "\n";
      // std::cout << "decrypt update expected outlen: " << plaintext.size()
      //           << "\n";
      // std::cout << "decrypt update outlen: " << len << "\n";

      assert(static_cast<size_t>(len) <= plaintext.size());
      plaintext.resize(len);

      state = State::DecryptionInProgress;

      return plaintext;
   }

   std::expected<Bytes, Error> decryptFinal()
   {
      if (state != State::DecryptionInProgress)
      {
         return std::unexpected(ErrorCode::DecryptFinalNotAllowed);
      }

      Bytes plaintext(info.blockSize);

      // Error indicates decryption failure or authentication failure.
      int len  = 0;
      auto res = EVP_DecryptFinal_ex(ctx.get(), plaintext.udata(), &len);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DecryptionFailure};
      }

      // std::cout << "decrypt final expected outlen: " << info.blockSize <<
      // "\n"; std::cout << "decrypt final outlen: " << len << "\n";

      assert(static_cast<size_t>(len) <= plaintext.size());
      plaintext.resize(len);

      state = State::Uninitialized;

      return plaintext;
   }
};

std::expected<AuthSymmetricCipher, Error> AuthSymmetricCipher::create(
   Bytes key, AuthSymmetricCipherAlgorithm alg)
{
   auto cipher = ossl::getCipher(alg);
   if (!cipher.has_value())
   {
      return std::unexpected{cipher.error()};
   }

   auto info = ossl::getInfo(cipher.value());
   if (!info.has_value())
   {
      return std::unexpected{info.error()};
   }

   if (key.size() < info->keyLength)
   {
      return std::unexpected{ErrorCode::InvalidKeyLength};
   }

   auto ctx = ossl::makeCipherContext(cipher.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto tagLength = getTagLength(alg, ctx.value());
   if (!tagLength)
   {
      return std::unexpected(tagLength.error());
   }

   AuthSymmetricCipher res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(key),
                                   std::move(info.value()),
                                   tagLength.value(),
                                   std::move(cipher.value()),
                                   std::move(ctx.value()));
   return res;
}

AuthSymmetricCipher::~AuthSymmetricCipher() = default;

AuthSymmetricCipherAlgorithm AuthSymmetricCipher::getAlgorithm() const
{
   return d_->alg;
}
AlgorithmInfo AuthSymmetricCipher::getAlgorithmInfo() const
{
   return d_->info;
}

std::expected<AuthSymmetricCipher::EncryptionResult, Error>
AuthSymmetricCipher::encrypt(BytesView plaintext,
                             BytesView iv,
                             std::optional<BytesView> aad)
{
   if (auto res = d_->encryptInit(iv); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   if (aad.has_value())
   {
      // CCM algorithm needs to know the plaintext length before setting AAD.
      auto plaintextLen = d_->info.mode == Mode::CCM ?
                             std::optional<size_t>(plaintext.size()) :
                             std::nullopt;

      if (auto res = d_->encryptAAD(aad.value(), plaintextLen);
          !res.has_value())
      {
         return std::unexpected(res.error());
      }
   }

   auto enc1 = d_->encryptUpdate(plaintext);
   if (!enc1.has_value())
   {
      return std::unexpected(enc1.error());
   }
   Bytes ciphertext = std::move(enc1.value());

   auto enc2 = d_->encryptFinal();
   if (!enc2.has_value())
   {
      return std::unexpected(enc2.error());
   }
   ciphertext += enc2->ciphertext;

   return EncryptionResult{std::move(ciphertext), std::move(enc2->tag)};
}

std::expected<Bytes, Error> AuthSymmetricCipher::decrypt(
   BytesView ciphertext,
   BytesView iv,
   BytesView tag,
   std::optional<BytesView> aad)
{
   if (auto res = d_->decryptInit(iv, tag); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   if (aad.has_value())
   {
      // CCM algorithm needs to know the ciphertext length before setting AAD.
      auto ciphertextLen = d_->info.mode == Mode::CCM ?
                              std::optional<size_t>(ciphertext.size()) :
                              std::nullopt;

      if (auto res = d_->decryptAAD(aad.value(), ciphertextLen);
          !res.has_value())
      {
         return std::unexpected(res.error());
      }
   }

   auto dec1 = d_->decryptUpdate(ciphertext);
   if (!dec1.has_value())
   {
      return std::unexpected(dec1.error());
   }
   Bytes plaintext = std::move(dec1.value());

   // CCM algorithm update() performs the final decryption + authentication.
   // The call to final() is not required in this case but is harmless.
   // if (d_->info.mode == Mode::CCM)
   // {
   //    return plaintext;
   // }

   auto dec2 = d_->decryptFinal();
   if (!dec2.has_value())
   {
      return std::unexpected(dec2.error());
   }
   plaintext += dec2.value();

   return plaintext;
}

std::expected<void, Error> AuthSymmetricCipher::encryptInit(BytesView iv)
{
   return d_->encryptInit(iv);
}

std::expected<void, Error> AuthSymmetricCipher::encryptAAD(
   BytesView aad, std::optional<size_t> ptlen)
{
   return d_->encryptAAD(aad, ptlen);
}

std::expected<Bytes, Error> AuthSymmetricCipher::encryptUpdate(
   BytesView plaintext)
{
   return d_->encryptUpdate(plaintext);
}

std::expected<AuthSymmetricCipher::EncryptionResult, Error>
AuthSymmetricCipher::encryptFinal()
{
   return d_->encryptFinal();
}

std::expected<void, Error> AuthSymmetricCipher::decryptInit(BytesView iv,
                                                            BytesView tag)
{
   return d_->decryptInit(iv, tag);
}

std::expected<void, Error> AuthSymmetricCipher::decryptAAD(
   BytesView aad, std::optional<size_t> ctlen)
{
   return d_->decryptAAD(aad, ctlen);
}

std::expected<Bytes, Error> AuthSymmetricCipher::decryptUpdate(
   BytesView ciphertext)
{
   return d_->decryptUpdate(ciphertext);
}

std::expected<Bytes, Error> AuthSymmetricCipher::decryptFinal()
{
   return d_->decryptFinal();
}

} // namespace grypt
