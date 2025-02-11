#include "osslutil.h"

#include <cassert>
#include <grypt/algorithm.h>
#include <grypt/randombytes.h>
#include <grypt/symmetriccipher.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace grypt
{

struct SymmetricCipher::Data
{
   enum class State
   {
      Uninitialized,
      EncryptionInitialized,
      DecryptionInitialized,
      EncryptionInProgress,
      DecryptionInProgress
   };

   const SymmetricCipherAlgorithm alg;
   const Bytes key;
   const AlgorithmInfo info;
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

   std::expected<Bytes, Error> encryptUpdate(BytesView plaintext)
   {
      if (state != State::EncryptionInitialized &&
          state != State::EncryptionInProgress)
      {
         return std::unexpected(ErrorCode::EncryptUpdateNotAllowed);
      }

      // You'd assume the output size would be the same as the input size
      // (for stream ciphers) or a multiple of the block size (for block
      // ciphers)... it turns out key wrap ciphers are weird, will add extra
      // 2 x block size just to be safe.
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

   std::expected<Bytes, Error> encryptFinal()
   {
      if (state != State::EncryptionInProgress)
      {
         return std::unexpected(ErrorCode::EncryptFinalNotAllowed);
      }

      // Output can be at most a block.
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

      state = State::Uninitialized;

      return ciphertext;
   }

   std::expected<void, Error> decryptInit(BytesView iv)
   {
      if (iv.size() < info.ivLength)
      {
         return std::unexpected{ErrorCode::InvalidIVLength};
      }

      auto res = EVP_DecryptInit_ex2(
         ctx.get(), nullptr, key.udata(), iv.udata(), nullptr);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DecryptionFailure};
      }

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

      // Output size <= input size
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

      // Output can be at most a block.
      Bytes plaintext(info.blockSize);

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

std::expected<SymmetricCipher, Error> SymmetricCipher::create(
   Bytes key, SymmetricCipherAlgorithm alg)
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

   SymmetricCipher res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(key),
                                   std::move(info.value()),
                                   std::move(cipher.value()),
                                   std::move(ctx.value()));
   return res;
}

SymmetricCipher::~SymmetricCipher() = default;

SymmetricCipherAlgorithm SymmetricCipher::getAlgorithm() const
{
   return d_->alg;
}
AlgorithmInfo SymmetricCipher::getAlgorithmInfo() const
{
   return d_->info;
}

std::expected<Bytes, Error> SymmetricCipher::encrypt(BytesView plaintext,
                                                     BytesView iv)
{
   if (auto res = d_->encryptInit(iv); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   auto res = d_->encryptUpdate(plaintext);
   if (!res.has_value())
   {
      return std::unexpected(res.error());
   }
   Bytes ciphertext = std::move(res.value());

   res = d_->encryptFinal();
   if (!res.has_value())
   {
      return std::unexpected(res.error());
   }
   ciphertext += res.value();

   return ciphertext;
}

std::expected<Bytes, Error> SymmetricCipher::decrypt(BytesView ciphertext,
                                                     BytesView iv)
{
   if (auto res = d_->decryptInit(iv); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   auto res = d_->decryptUpdate(ciphertext);
   if (!res.has_value())
   {
      return std::unexpected(res.error());
   }

   Bytes plaintext = std::move(res.value());

   res = d_->decryptFinal();
   if (!res.has_value())
   {
      return std::unexpected(res.error());
   }
   plaintext += res.value();

   return plaintext;
}

std::expected<void, Error> SymmetricCipher::encryptInit(BytesView iv)
{
   return d_->encryptInit(iv);
}

std::expected<Bytes, Error> SymmetricCipher::encryptUpdate(BytesView plaintext)
{
   return d_->encryptUpdate(plaintext);
}

std::expected<Bytes, Error> SymmetricCipher::encryptFinal()
{
   return d_->encryptFinal();
}

std::expected<void, Error> SymmetricCipher::decryptInit(BytesView iv)
{
   return d_->decryptInit(iv);
}

std::expected<Bytes, Error> SymmetricCipher::decryptUpdate(BytesView ciphertext)
{
   return d_->decryptUpdate(ciphertext);
}

std::expected<Bytes, Error> SymmetricCipher::decryptFinal()
{
   return d_->decryptFinal();
}

} // namespace grypt
