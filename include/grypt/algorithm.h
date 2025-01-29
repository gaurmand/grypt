#ifndef GRYPT_ALGORITHM_H
#define GRYPT_ALGORITHM_H

#include <cstdlib>
#include <expected>
#include <grypt/error.h>
#include <ostream>
#include <variant>

namespace grypt
{

enum class NullAlgorithm
{
};

enum class SymmetricCipherAlgorithm
{
   AES_128_CBC,
   AES_128_CBC_CTS,
   AES_128_CFB,
   AES_128_CFB1,
   AES_128_CFB8,
   AES_128_CTR,
   AES_128_ECB,
   AES_128_OFB,
   AES_128_XTS,
   AES_128_WRAP,
   AES_128_WRAP_PAD,
   AES_128_WRAP_INV,
   AES_128_WRAP_PAD_INV,

   AES_192_CBC,
   AES_192_CBC_CTS,
   AES_192_CFB,
   AES_192_CFB1,
   AES_192_CFB8,
   AES_192_CTR,
   AES_192_ECB,
   AES_192_OFB,
   AES_192_WRAP,
   AES_192_WRAP_PAD,
   AES_192_WRAP_INV,
   AES_192_WRAP_PAD_INV,

   AES_256_CBC,
   AES_256_CBC_CTS,
   AES_256_CFB,
   AES_256_CFB1,
   AES_256_CFB8,
   AES_256_CTR,
   AES_256_ECB,
   AES_256_OFB,
   AES_256_XTS,
   AES_256_WRAP,
   AES_256_WRAP_PAD,
   AES_256_WRAP_INV,
   AES_256_WRAP_PAD_INV,

   CHACHA20,
   CHACHA20_POLY1305,
};

enum class AuthSymmetricCipherAlgorithm
{
   AES_128_CCM,
   AES_128_GCM,
   AES_128_GCM_SIV,
   AES_128_OCB,
   AES_128_SIV,

   AES_192_CCM,
   AES_192_GCM,
   AES_192_GCM_SIV,
   AES_192_OCB,
   AES_192_SIV,

   AES_256_CCM,
   AES_256_GCM,
   AES_256_GCM_SIV,
   AES_256_OCB,
   AES_256_SIV
};

using Algorithm = std::variant<NullAlgorithm,
                               SymmetricCipherAlgorithm,
                               AuthSymmetricCipherAlgorithm>;

enum class Mode
{
   None,
   CBC,
   CCM,
   CFB,
   CTR,
   ECB,
   GCM,
   OCB,
   OFB,
   SIV,
   WRAP,
   XTS,
   STREAM
};

struct AlgorithmInfo
{
   size_t keyLength{0};
   size_t ivLength{0};
   size_t blockSize{0};
   Mode mode{Mode::None};

   bool operator==(const AlgorithmInfo&) const = default;
};

std::expected<AlgorithmInfo, Error> getInfo(Algorithm alg);

} // namespace grypt

#endif
