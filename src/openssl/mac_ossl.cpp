#include "osslutil.h"

#include <cassert>
#include <grypt/mac.h>
#include <openssl/conf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <vector>

namespace grypt
{

namespace
{

std::expected<ossl::evp_mac_ptr, Error> getMAC(MAC::Algorithm alg)
{
   auto str = ossl::toString(alg);
   ossl::evp_mac_ptr mac{EVP_MAC_fetch(nullptr, str.data(), nullptr)};
   if (!mac)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::InitializeCipherFailed);
   }
   return mac;
}

std::vector<OSSL_PARAM> makeParams(
   std::optional<HashAlgorithm> halg = std::nullopt,
   std::optional<CMACAlgorithm> calg = std::nullopt,
   std::optional<GMACAlgorithm> galg = std::nullopt)
{
   std::vector<OSSL_PARAM> res;

   if (halg.has_value())
   {
      auto hashName  = ossl::toString(halg.value());
      auto hashParam = OSSL_PARAM_construct_utf8_string(
         OSSL_MAC_PARAM_DIGEST, const_cast<char*>(hashName.data()), 0);
      res.emplace_back(std::move(hashParam));
   }
   if (calg.has_value())
   {
      auto cipherName  = ossl::toString(calg.value());
      auto cipherParam = OSSL_PARAM_construct_utf8_string(
         OSSL_MAC_PARAM_CIPHER, const_cast<char*>(cipherName.data()), 0);
      res.emplace_back(std::move(cipherParam));
   }
   if (galg.has_value())
   {
      auto cipherName  = ossl::toString(galg.value());
      auto cipherParam = OSSL_PARAM_construct_utf8_string(
         OSSL_MAC_PARAM_CIPHER, const_cast<char*>(cipherName.data()), 0);
      res.emplace_back(std::move(cipherParam));
   }

   res.push_back(OSSL_PARAM_END);

   return res;
}

MAC::AlgorithmInfo getInfo(const ossl::evp_mac_ctx_ptr& ctx)
{
   auto sz = EVP_MAC_CTX_get_mac_size(ctx.get());
   assert(sz > 0);
   return MAC::AlgorithmInfo{sz};
}

std::expected<ossl::evp_mac_ctx_ptr, Error> makeContext(
   const ossl::evp_mac_ptr& md,
   BytesView key,
   const std::optional<std::vector<OSSL_PARAM>>& params = std::nullopt)
{
   ossl::evp_mac_ctx_ptr ctx{EVP_MAC_CTX_new(md.get())};
   if (!ctx)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::InitializeCipherFailed};
   }

   auto res = EVP_MAC_init(
      ctx.get(), key.udata(), key.size(), params ? params->data() : nullptr);
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::MACFailure};
   }

   return ctx;
}

} // namespace

struct MAC::Data
{
   enum class State
   {
      Uninitialized,
      MACInitialized,
      MACInProgress,
   };

   const MAC::Algorithm alg;
   const MAC::AlgorithmInfo info;
   const Bytes key;
   const std::optional<Bytes> iv;
   ossl::evp_mac_ptr md;
   ossl::evp_mac_ctx_ptr ctx;
   State state{State::Uninitialized};

   std::optional<std::array<OSSL_PARAM, 2>> getIVParams()
   {
      if (!iv.has_value())
      {
         return std::nullopt;
      }

      std::array<OSSL_PARAM, 2> params = {{OSSL_PARAM_END, OSSL_PARAM_END}};
      params[0]                        = OSSL_PARAM_construct_octet_string(
         OSSL_CIPHER_PARAM_IV,
         const_cast<unsigned char*>(iv->udata()),
         iv->size());

      return params;
   }

   std::expected<void, Error> macInit()
   {
      // IV parameters must be set each time we do a MAC operations, unlike
      // other parameters that we can just set once at the start.
      auto params = getIVParams();

      auto res =
         EVP_MAC_init(ctx.get(), nullptr, 0, params ? params->data() : nullptr);
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::MACFailure};
      }

      state = State::MACInitialized;

      return {};
   }

   std::expected<void, Error> macUpdate(BytesView data)
   {
      if (state != State::MACInitialized && state != State::MACInProgress)
      {
         return std::unexpected(ErrorCode::MACUpdateNotAllowed);
      }

      auto res = EVP_MAC_update(ctx.get(), data.udata(), data.size());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::MACFailure};
      }

      state = State::MACInProgress;

      return {};
   }

   std::expected<Bytes, Error> macFinal()
   {
      if (state != State::MACInProgress)
      {
         return std::unexpected(ErrorCode::MACFinalNotAllowed);
      }

      Bytes tag(info.tagLength);

      size_t len{0};
      auto res = EVP_MAC_final(ctx.get(), tag.udata(), &len, tag.size());

      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected{ErrorCode::MACFailure};
      };

      // std::cout << "len: " << len << std::endl;
      // std::cout << "taglen: " << info.tagLength << std::endl;
      assert(len == info.tagLength);

      state = State::Uninitialized;

      return tag;
   }
};

std::expected<MAC, Error> MAC::createHMAC(Bytes key, HashAlgorithm halg)
{
   // HMAC does not support hash algs with variable length digests
   switch (halg)
   {
      case HashAlgorithm::KECCAK_KMAC_128:
      case HashAlgorithm::KECCAK_KMAC_256:
      case HashAlgorithm::SHAKE_128:
      case HashAlgorithm::SHAKE_256:
         return std::unexpected{ErrorCode::InvalidArguments};
      default: break;
   }

   auto alg = Algorithm::HMAC;

   auto mac = getMAC(alg);
   if (!mac.has_value())
   {
      return std::unexpected{mac.error()};
   }

   auto params = makeParams(halg);
   auto ctx    = makeContext(mac.value(), key, params);
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(ctx.value());

   MAC res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(info),
                                   std::move(key),
                                   std::nullopt,
                                   std::move(mac.value()),
                                   std::move(ctx.value()));
   return res;
}

std::expected<MAC, Error> MAC::createCMAC(Bytes key, CMACAlgorithm calg)
{
   auto alg = Algorithm::CMAC;

   auto mac = getMAC(alg);
   if (!mac.has_value())
   {
      return std::unexpected{mac.error()};
   }

   auto params = makeParams({}, calg);
   auto ctx    = makeContext(mac.value(), key, params);
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(ctx.value());

   MAC res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(info),
                                   std::move(key),
                                   std::nullopt,
                                   std::move(mac.value()),
                                   std::move(ctx.value()));
   return res;
}

std::expected<MAC, Error> MAC::createGMAC(Bytes key,
                                          Bytes iv,
                                          GMACAlgorithm galg)
{
   auto alg = Algorithm::GMAC;

   auto mac = getMAC(alg);
   if (!mac.has_value())
   {
      return std::unexpected{mac.error()};
   }

   auto params = makeParams({}, {}, galg);
   auto ctx    = makeContext(mac.value(), key, params);
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(ctx.value());

   MAC res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(info),
                                   std::move(key),
                                   std::move(iv),
                                   std::move(mac.value()),
                                   std::move(ctx.value()));
   return res;
}

std::expected<MAC, Error> MAC::create(Bytes key, MACAlgorithm alg)
{
   // Other factory functions should be used for these mac algorithms
   switch (alg)
   {
      case MACAlgorithm::HMAC:
      case MACAlgorithm::CMAC:
      case MACAlgorithm::GMAC:
         return std::unexpected{ErrorCode::InvalidArguments};
      default: break;
   }

   auto mac = getMAC(alg);
   if (!mac.has_value())
   {
      return std::unexpected{mac.error()};
   }

   auto ctx = makeContext(mac.value(), key);
   if (!ctx.has_value())
   {
      return std::unexpected(ctx.error());
   }

   auto info = getInfo(ctx.value());

   MAC res;
   res.d_ = std::make_unique<Data>(alg,
                                   std::move(info),
                                   std::move(key),
                                   std::nullopt,
                                   std::move(mac.value()),
                                   std::move(ctx.value()));
   return res;
}

MAC::~MAC() = default;

MAC::Algorithm MAC::algorithm() const
{
   return d_->alg;
}

MAC::AlgorithmInfo MAC::info() const
{
   return d_->info;
}

std::expected<Bytes, Error> MAC::sign(BytesView data)
{
   if (auto res = d_->macInit(); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   if (auto res = d_->macUpdate(data); !res.has_value())
   {
      return std::unexpected(res.error());
   }

   return d_->macFinal();
}

std::expected<bool, Error> MAC::verify(BytesView data, BytesView tag)
{
   if (tag.size() != d_->info.tagLength)
   {
      return std::unexpected(ErrorCode::InvalidTagLength);
   }

   auto res = sign(data);
   if (!res.has_value())
   {
      return std::unexpected(res.error());
   }

   return res.value() == tag;
}

std::expected<void, Error> MAC::macInit()
{
   return d_->macInit();
}

std::expected<void, Error> MAC::macUpdate(BytesView data)
{
   return d_->macUpdate(data);
}

std::expected<Bytes, Error> MAC::macFinal()
{
   return d_->macFinal();
}

} // namespace grypt
