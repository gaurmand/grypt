#include "osslutil.h"

#include <cassert>
#include <grypt/hash.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace grypt
{

namespace
{

std::expected<ossl::evp_md_ptr, Error> getMD(Hash::Algorithm alg)
{
   auto str = ossl::toString(alg);
   ossl::evp_md_ptr md{EVP_MD_fetch(nullptr, str.data(), nullptr)};
   if (!md)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::InitializeCipherFailed);
   }
   return md;
}

std::expected<Hash::AlgorithmInfo, Error> getInfo(const ossl::evp_md_ptr& md)
{
   auto sz = EVP_MD_get_size(md.get());
   assert(sz > 0);
   return Hash::AlgorithmInfo{static_cast<size_t>(sz)};
}

std::expected<ossl::evp_md_ctx_ptr, Error> makeContext(
   const ossl::evp_md_ptr& md)
{
   ossl::evp_md_ctx_ptr ctx{EVP_MD_CTX_new()};
   if (!ctx)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   auto res = EVP_DigestInit_ex2(ctx.get(), md.get(), nullptr);
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   return ctx;
}

} // namespace

struct Hash::Data
{
   enum class State
   {
      Uninitialized,
      DigestInitialized,
      DigestInProgress,
   };

   const Hash::Algorithm alg;
   const AlgorithmInfo info;
   ossl::evp_md_ptr md;
   ossl::evp_md_ctx_ptr ctx;
   State state{State::Uninitialized};

   std::expected<void, Error> digestInit()
   {
      auto res = EVP_DigestInit_ex2(ctx.get(), nullptr, nullptr);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DigestFailure};
      }

      state = State::DigestInitialized;

      return {};
   }

   std::expected<void, Error> digestUpdate(BytesView data)
   {
      if (state != State::DigestInitialized && state != State::DigestInProgress)
      {
         return std::unexpected(ErrorCode::DigestUpdateNotAllowed);
      }

      auto res = EVP_DigestUpdate(ctx.get(), data.udata(), data.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DigestFailure};
      }

      state = State::DigestInProgress;

      return {};
   }

   std::expected<Bytes, Error> digestFinal()
   {
      if (state != State::DigestInProgress)
      {
         return std::unexpected(ErrorCode::DigestFinalNotAllowed);
      }

      Bytes digest(info.digestLength);

      unsigned int len{0};
      auto res = EVP_DigestFinal_ex(ctx.get(), digest.udata(), &len);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::DigestFailure};
      };

      assert(len == digest.size());

      state = State::Uninitialized;

      return digest;
   }
};

std::expected<Hash, Error> Hash::create(Hash::Algorithm alg)
{
   auto md = getMD(alg);
   if (!md.has_value())
   {
      return std::unexpected{md.error()};
   }

   auto info = getInfo(md.value());
   if (!info.has_value())
   {
      return std::unexpected{info.error()};
   }

   auto ctx = makeContext(md.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   Hash res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(info.value()),
                                   std::move(md.value()),
                                   std::move(ctx.value()));

   return res;
}

Hash::~Hash() = default;

Hash::Algorithm Hash::algorithm() const
{
   return d_->alg;
}

Hash::AlgorithmInfo Hash::info() const
{
   return d_->info;
}

std::expected<Bytes, Error> Hash::digest(BytesView data)
{
   if (auto res = d_->digestInit(); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   if (auto res = d_->digestUpdate(data); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   return d_->digestFinal();
}

std::expected<void, Error> Hash::digestInit()
{
   return d_->digestInit();
}

std::expected<void, Error> Hash::digestUpdate(BytesView data)
{
   return d_->digestUpdate(data);
}

std::expected<Bytes, Error> Hash::digestFinal()
{
   return d_->digestFinal();
}

} // namespace grypt
