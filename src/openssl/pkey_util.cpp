#include "pkey_util.h"

#include <cstdio>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

namespace grypt::ossl
{

namespace
{

int toSelection(const std::optional<PKeyInfo>& hints)
{
   if (!hints.has_value())
      return 0;

   switch (hints->selection)
   {
      case PKeyInfo::Selection::PUBLIC: return EVP_PKEY_PUBLIC_KEY;
      case PKeyInfo::Selection::KEYPAIR: return EVP_PKEY_KEYPAIR;
      case PKeyInfo::Selection::AUTO:
      default: return 0;
   }
}

std::optional<std::string_view> toInputType(
   const std::optional<PKeyInfo>& hints)
{
   if (!hints.has_value())
      return {};

   switch (hints->type)
   {
      case PKeyInfo::InputType::PEM: return "PEM";
      case PKeyInfo::InputType::DER: return "DER";
      case PKeyInfo::InputType::AUTO:
      default: return {};
   }
}

} // namespace

std::string_view toString(RSAPadding pad)
{
   switch (pad)
   {
      case RSAPadding::PKCS1: return OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
      case RSAPadding::OAEP: return OSSL_PKEY_RSA_PAD_MODE_OAEP;
      case RSAPadding::X931: return OSSL_PKEY_RSA_PAD_MODE_X931;
      case RSAPadding::PSS: return OSSL_PKEY_RSA_PAD_MODE_PSS;
      case RSAPadding::None: return OSSL_PKEY_RSA_PAD_MODE_NONE;
      default: return {};
   }
}

std::string_view toString(DigitalSignatureAlgorithm alg)
{
   using Alg = DigitalSignatureAlgorithm;

   switch (alg)
   {
      case Alg::DSA: return "DSA";
      case Alg::ECDSA: return "EC";
      case Alg::ED25519: return "Ed25519";
      case Alg::ED448: return "Ed448";
      case Alg::RSA: return "RSA";
      default: return {};
   }
}

std::expected<evp_pkey_ptr, Error> makePKeyFromData(
   std::string_view algName,
   BytesView data,
   const std::optional<PKeyInfo>& hints)
{
   EVP_PKEY* pkey = nullptr;

   const int selection  = toSelection(hints);
   const auto inputType = toInputType(hints);
   decoder_ctx_ptr decoder{
      OSSL_DECODER_CTX_new_for_pkey(&pkey,
                                    inputType ? inputType->data() : nullptr,
                                    nullptr,
                                    algName.data(),
                                    selection,
                                    nullptr,
                                    nullptr)};
   if (!decoder)
   {
      handleError();
      return std::unexpected(ErrorCode::KeyParseFailure);
   }

   auto buf = data.udata();
   auto sz  = data.size();

   auto res = OSSL_DECODER_from_data(decoder.get(), &buf, &sz);
   if (res != ERR_LIB_NONE || pkey == nullptr)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::KeyParseFailure);
   }

   return ossl::evp_pkey_ptr{pkey};
}

std::expected<evp_pkey_ptr, Error> makePKeyFromFile(
   std::string_view algName,
   std::filesystem::path path,
   const std::optional<PKeyInfo>& hints)
{
   auto* fp = std::fopen(path.c_str(), "r");
   if (!fp)
   {
      return std::unexpected(ErrorCode::KeyParseFailure);
   }

   EVP_PKEY* pkey = nullptr;

   const int selection  = toSelection(hints);
   const auto inputType = toInputType(hints);

   ossl::decoder_ctx_ptr decoder{
      OSSL_DECODER_CTX_new_for_pkey(&pkey,
                                    inputType ? inputType->data() : nullptr,
                                    nullptr,
                                    algName.data(),
                                    selection,
                                    nullptr,
                                    nullptr)};
   if (!decoder)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::KeyParseFailure);
   }

   auto res = OSSL_DECODER_from_fp(decoder.get(), fp);
   if (res != ERR_LIB_NONE || pkey == nullptr)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::KeyParseFailure);
   }

   return ossl::evp_pkey_ptr{pkey};
}

std::expected<ossl::evp_pkey_ctx_ptr, Error> makeContext(
   const ossl::evp_pkey_ptr& pkey,
   const std::optional<std::vector<OSSL_PARAM>>& params)
{
   ossl::evp_pkey_ctx_ptr ctx{
      EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr)};
   if (ctx == nullptr)
   {
      ossl::handleError();
      return std::unexpected(ErrorCode::InitializeCipherFailed);
   }

   if (params.has_value())
   {
      auto res = EVP_PKEY_CTX_set_params(ctx.get(), params->data());
      if (res != ERR_LIB_NONE)
      {
         ossl::handleError();
         return std::unexpected(ErrorCode::KeyParseFailure);
      }
   }

   return ctx;
}

std::expected<ossl::evp_pkey_ptr, Error> makePKey(std::string_view name,
                                                  const AsymKeyParam& keyParam)
{

   return std::visit(grypt::make_visitor{[name](BytesView keyData) {
      return ossl::makePKeyFromData(name, keyData);
   },
                                         [name](std::filesystem::path keyFile) {
      return ossl::makePKeyFromFile(name, keyFile);
   }},
                     keyParam);
}

std::vector<OSSL_PARAM> makeRSAParams(RSAPadding pad)
{
   std::vector<OSSL_PARAM> params;

   auto padName  = toString(pad);
   auto padParam = OSSL_PARAM_construct_utf8_string(
      OSSL_SIGNATURE_PARAM_PAD_MODE, const_cast<char*>(padName.data()), 0);
   params.emplace_back(std::move(padParam));
   params.push_back(OSSL_PARAM_END);

   return params;
}

} // namespace grypt::ossl
