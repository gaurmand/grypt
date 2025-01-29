#include "osslutil.h"

#include <grypt/algorithm.h>

namespace grypt
{

std::expected<AlgorithmInfo, Error> getInfo(Algorithm alg)
{
   auto info = std::visit<std::expected<AlgorithmInfo, Error>>(
      make_visitor{[](NullAlgorithm) -> std::expected<AlgorithmInfo, Error> {
      return {};
   },
                   [](SymmetricCipherAlgorithm alg)
                      -> std::expected<AlgorithmInfo, Error> {
      auto cipher = ossl::getCipher(alg);
      if (!cipher.has_value())
      {
         return std::unexpected(cipher.error());
      }
      return ossl::getInfo(cipher.value());
   },
                   [](AuthSymmetricCipherAlgorithm alg)
                      -> std::expected<AlgorithmInfo, Error> {
      auto cipher = ossl::getCipher(alg);
      if (!cipher.has_value())
      {
         return std::unexpected(cipher.error());
      }
      return ossl::getInfo(cipher.value());
   }},
      alg);

   return info;
}

} // namespace grypt
