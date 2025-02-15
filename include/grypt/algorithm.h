#ifndef GRYPT_ALGORITHM_H
#define GRYPT_ALGORITHM_H

#include <cstdlib>
#include <expected>
#include <grypt/error.h>
#include <optional>
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

   CHACHA20
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
   AES_256_SIV,

   CHACHA20_POLY1305
};

enum class HashAlgorithm
{
   BLAKE2S_256,
   BLAKE2B_512,
   MD5,
   MD5_SHA1,
   RIPEMD_160,
   SHA1,
   SHA2_224,
   SHA2_256,
   SHA2_384,
   SHA2_512,
   SHA2_512_224,
   SHA2_512_256,
   SHA3_224,
   SHA3_256,
   SHA3_384,
   SHA3_512,
   SHAKE_128,
   SHAKE_256,
   KECCAK_KMAC_128,
   KECCAK_KMAC_256,
   SM3
};

// Note: Poly1305 is complicated to use, will leave out for now.
enum class MACAlgorithm
{
   BLAKE2BMAC,
   BLAKE2SMAC,
   CMAC,
   GMAC,
   HMAC,
   KMAC_128,
   KMAC_256,
   SIPHASH,
   // Poly1305
};

enum class CMACAlgorithm
{
   AES_128_CBC,
   AES_192_CBC,
   AES_256_CBC,
};

enum class GMACAlgorithm
{
   AES_128_GCM,
   AES_192_GCM,
   AES_256_GCM,
};

enum class DigitalSignatureAlgorithm
{
   DSA,
   ECDSA,
   ED25519,
   ED448,
   RSA,
   // ML_DSA (OpenSSL 3.5)
};

enum class RSAPadding
{
   None,
   PKCS1,
   OAEP, // encrypt/decrypt only
   X931, // sign/verify only
   PSS   // sign/verify only
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
