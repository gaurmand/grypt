#include "osslutil.h"
#include "pkey_util.h"

#include <cassert>
#include <grypt/algorithm.h>
#include <grypt/digitalsignature.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

namespace grypt
{

namespace
{

std::expected<ossl::evp_md_ctx_ptr, Error> makeContext()
{
   ossl::evp_md_ctx_ptr ctx{EVP_MD_CTX_new()};
   if (!ctx)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   return ctx;
}

DigitalSignature::AlgorithmInfo getInfo(const ossl::evp_pkey_ptr& pkey,
                                        const ossl::evp_pkey_ctx_ptr& ctx)
{
   DigitalSignature::AlgorithmInfo info;
   info.keyLength    = EVP_PKEY_get_bits(pkey.get());
   info.isPrivateKey = EVP_PKEY_private_check(ctx.get()) == ERR_LIB_NONE;

   return info;
}

} // namespace

struct DigitalSignature::Data
{
   enum class State
   {
      Uninitialized,
      SignInitialized,
      VerifyInitialized,
      SignInProgress,
      VerifyInProgress
   };

   const Algorithm alg;
   const AlgorithmInfo info;
   const std::optional<HashAlgorithm> halg;
   const std::optional<RSAPadding> pad;
   ossl::evp_md_ctx_ptr ctx;
   ossl::evp_pkey_ptr pkey;
   State state{State::Uninitialized};

   std::expected<void, Error> signInit()
   {
      if (!info.isPrivateKey)
      {
         return std::unexpected(ErrorCode::PublicKeySignFailure);
      }

      std::optional hash   = halg ? ossl::toString(halg.value()) :
                                    std::optional<std::string_view>();
      std::optional params = pad ? ossl::makeRSAParams(pad.value()) :
                                   std::optional<std::vector<OSSL_PARAM>>();

      auto res = EVP_DigestSignInit_ex(ctx.get(),
                                       nullptr,
                                       hash ? hash->data() : nullptr,
                                       nullptr,
                                       nullptr,
                                       pkey.get(),
                                       params ? params->data() : nullptr);

      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSSignFailed);
      }

      state = State::SignInitialized;

      return {};
   }

   std::expected<void, Error> signUpdate(BytesView data)
   {
      if (state != State::SignInitialized && state != State::SignInProgress)
      {
         return std::unexpected(ErrorCode::SignUpdateNotAllowed);
      }

      auto res = EVP_DigestSignUpdate(ctx.get(), data.udata(), data.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSSignFailed);
      }

      state = State::SignInProgress;

      return {};
   }

   std::expected<Bytes, Error> signFinal()
   {
      if (state != State::SignInProgress)
      {
         return std::unexpected(ErrorCode::SignFinalNotAllowed);
      }

      size_t len{0};
      auto res = EVP_DigestSignFinal(ctx.get(), nullptr, &len);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSSignFailed);
      }

      Bytes tag(len);
      res = EVP_DigestSignFinal(ctx.get(), tag.udata(), &len);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSSignFailed);
      }

      // std::cout << "len: " << len << std::endl;
      // std::cout << "tag size: " << tag.size() << std::endl;

      assert(len <= tag.size());
      tag.resize(len);

      state = State::Uninitialized;

      return tag;
   }

   std::expected<void, Error> verifyInit()
   {
      std::optional hash   = halg ? ossl::toString(halg.value()) :
                                    std::optional<std::string_view>();
      std::optional params = pad ? ossl::makeRSAParams(pad.value()) :
                                   std::optional<std::vector<OSSL_PARAM>>();

      auto res = EVP_DigestVerifyInit_ex(ctx.get(),
                                         nullptr,
                                         hash ? hash->data() : nullptr,
                                         nullptr,
                                         nullptr,
                                         pkey.get(),
                                         params ? params->data() : nullptr);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSVerifyFailed);
      }

      state = State::VerifyInitialized;

      return {};
   }

   std::expected<void, Error> verifyUpdate(BytesView data)
   {
      if (state != State::VerifyInitialized && state != State::VerifyInProgress)
      {
         return std::unexpected(ErrorCode::VerifyUpdateNotAllowed);
      }

      auto res = EVP_DigestVerifyUpdate(ctx.get(), data.udata(), data.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSVerifyFailed);
      }

      state = State::VerifyInProgress;

      return {};
   }

   std::expected<bool, Error> verifyFinal(BytesView tag)
   {
      if (state != State::VerifyInProgress)
      {
         return std::unexpected(ErrorCode::VerifyFinalNotAllowed);
      }

      auto res = EVP_DigestVerifyFinal(ctx.get(), tag.udata(), tag.size());
      state    = State::Uninitialized;

      return res == ERR_LIB_NONE;
   }

   std::expected<Bytes, Error> signOneShot(BytesView data)
   {
      if (state != State::SignInitialized)
      {
         return std::unexpected(ErrorCode::SignUpdateNotAllowed);
      }

      size_t len{0};
      auto res =
         EVP_DigestSign(ctx.get(), nullptr, &len, data.udata(), data.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSSignFailed);
      }

      Bytes tag(len);
      res = EVP_DigestSign(
         ctx.get(), tag.udata(), &len, data.udata(), data.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::DSSignFailed);
      }

      // std::cout << "len: " << len << std::endl;
      // std::cout << "tag size: " << tag.size() << std::endl;

      assert(len <= tag.size());
      tag.resize(len);

      state = State::Uninitialized;

      return tag;
   }

   std::expected<bool, Error> verifyOneShot(BytesView data, BytesView tag)
   {
      if (state != State::VerifyInitialized)
      {
         return std::unexpected(ErrorCode::VerifyUpdateNotAllowed);
      }

      auto res = EVP_DigestVerify(
         ctx.get(), tag.udata(), tag.size(), data.udata(), data.size());
      state = State::Uninitialized;

      return res == ERR_LIB_NONE;
   }
};

std::expected<DigitalSignature, Error> DigitalSignature::create(
   Algorithm alg, AsymKeyParam keyParam, HashAlgorithm halg)
{
   auto name = ossl::toString(alg);
   auto pkey = ossl::makePKey(name, keyParam);
   if (!pkey.has_value())
   {
      return std::unexpected(pkey.error());
   }

   auto ctx = makeContext();
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto pctx = ossl::makeContext(pkey.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(pkey.value(), pctx.value());

   DigitalSignature res;
   res.d_ = std::make_unique<DigitalSignature::Data>(alg,
                                                     std::move(info),
                                                     halg,
                                                     std::nullopt,
                                                     std::move(ctx.value()),
                                                     std::move(pkey.value()));

   return res;
}

std::expected<DigitalSignature, Error> DigitalSignature::createED(
   Algorithm alg, AsymKeyParam keyParam)
{
   auto name = ossl::toString(alg);
   auto pkey = ossl::makePKey(name, keyParam);
   if (!pkey.has_value())
   {
      return std::unexpected(pkey.error());
   }

   auto ctx = makeContext();
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto pctx = ossl::makeContext(pkey.value());
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(pkey.value(), pctx.value());

   DigitalSignature res;
   res.d_ = std::make_unique<DigitalSignature::Data>(alg,
                                                     std::move(info),
                                                     std::nullopt,
                                                     std::nullopt,
                                                     std::move(ctx.value()),
                                                     std::move(pkey.value()));

   return res;
}

std::expected<DigitalSignature, Error> DigitalSignature::createRSA(
   AsymKeyParam keyParam, RSAPadding pad, std::optional<HashAlgorithm> halg)
{
   switch (pad)
   {
      case RSAPadding::OAEP:
         return std::unexpected{ErrorCode::InvalidArguments};
      default: break;
   }

   auto alg  = Algorithm::RSA;
   auto name = ossl::toString(alg);
   auto pkey = ossl::makePKey(name, keyParam);
   if (!pkey.has_value())
   {
      return std::unexpected(pkey.error());
   }

   auto ctx = makeContext();
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto pctx = ossl::makeContext(pkey.value());
   if (!pctx.has_value())
   {
      return std::unexpected(pctx.error());
   }

   auto info = getInfo(pkey.value(), pctx.value());

   DigitalSignature res;
   res.d_ = std::make_unique<DigitalSignature::Data>(alg,
                                                     std::move(info),
                                                     halg,
                                                     pad,
                                                     std::move(ctx.value()),
                                                     std::move(pkey.value()));
   return res;
}

std::expected<Bytes, Error> DigitalSignature::sign(BytesView data)
{
   if (auto res = d_->signInit(); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   // Some algorithms only work with the signOneShot(), so we prefer that.
   // if (auto res = d_->signUpdate(data); !res.has_value())
   // {
   //    return std::unexpected(res.error());
   // }
   // return d_->signFinal();

   return d_->signOneShot(data);
}

std::expected<bool, Error> DigitalSignature::verify(BytesView data,
                                                    BytesView tag)
{
   if (auto res = d_->verifyInit(); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   // Some algorithms only work with the verifyOneShot(), so we prefer that.
   // if (auto res = d_->verifyUpdate(data); !res.has_value())
   // {
   //    return std::unexpected(res.error());
   // }
   // return d_->verifyFinal(tag);

   return d_->verifyOneShot(data, tag);
}

std::expected<void, Error> DigitalSignature::signInit()
{
   return d_->signInit();
}
std::expected<void, Error> DigitalSignature::signUpdate(BytesView data)
{
   return d_->signUpdate(data);
}
std::expected<Bytes, Error> DigitalSignature::signFinal()
{
   return d_->signFinal();
}

std::expected<void, Error> DigitalSignature::verifyInit()
{
   return d_->verifyInit();
}
std::expected<void, Error> DigitalSignature::verifyUpdate(BytesView data)
{
   return d_->verifyUpdate(data);
}
std::expected<bool, Error> DigitalSignature::verifyFinal(BytesView tag)
{
   return d_->verifyFinal(tag);
}

DigitalSignature::Algorithm DigitalSignature::algorithm() const
{
   return d_->alg;
}

DigitalSignature::AlgorithmInfo DigitalSignature::info() const
{
   return d_->info;
}

DigitalSignature::~DigitalSignature() = default;

} // namespace grypt
