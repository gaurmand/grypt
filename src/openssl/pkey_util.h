#ifndef GRYPT_PKEY_UTIL_H
#define GRYPT_PKEY_UTIL_H

#include "osslutil.h"

#include <expected>
#include <filesystem>
#include <grypt/algorithm.h>
#include <grypt/asymkey.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <optional>
#include <string_view>
#include <vector>

namespace grypt::ossl
{

std::string_view toString(RSAPadding pad);
std::string_view toString(DigitalSignatureAlgorithm alg);

struct PKeyInfo
{
   enum class InputType
   {
      AUTO,
      DER,
      PEM
   };

   // enum class InputStruct
   // {
   //    AUTO,
   //    PKCS8,
   //    SubjectPublicKeyInfo
   // };

   enum class Selection
   {
      AUTO,
      PUBLIC,
      KEYPAIR
   };

   InputType type{InputType::AUTO};
   Selection selection{Selection::AUTO};
};

std::expected<evp_pkey_ptr, Error> makePKeyFromData(
   std::string_view algName,
   BytesView data,
   const std::optional<PKeyInfo>& hints = std::nullopt);

std::expected<evp_pkey_ptr, Error> makePKeyFromFile(
   std::string_view algName,
   std::filesystem::path path,
   const std::optional<PKeyInfo>& hints = std::nullopt);

std::expected<ossl::evp_pkey_ptr, Error> makePKey(std::string_view name,
                                                  const AsymKeyParam& keyParam);

std::expected<ossl::evp_pkey_ctx_ptr, Error> makeContext(
   const ossl::evp_pkey_ptr& pkey,
   const std::optional<std::vector<OSSL_PARAM>>& params = std::nullopt);

std::vector<OSSL_PARAM> makeRSAParams(RSAPadding pad);

} // namespace grypt::ossl

#endif
