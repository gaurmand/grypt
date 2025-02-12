#ifndef GRYPT_ASYMMETRICKEYCIPHER_H
#define GRYPT_ASYMMETRICKEYCIPHER_H

#include <expected>
#include <filesystem>
#include <grypt/algorithm.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <memory>

namespace grypt
{

/*!
   @brief A cipher that performs encryption with a public key and decryption
   with a private key.
*/
class AsymmetricCipher final
{
public:
   // Currently only supports RSA with different padding modes (could not get
   // SM2 to work).
   // For OAEP padding, the same hash function is used for MGF1 and OAEP.
   enum class Algorithm
   {
      RSA_NO_PAD,
      RSA_PKCS1,
      RSA_PKCS1_OAEP_MGF1_SHA1,
      RSA_PKCS1_OAEP_MGF1_SHA256,
      RSA_PKCS1_OAEP_MGF1_SHA512
   };

   struct AlgorithmInfo
   {
      size_t keyLength{0};          // modulus length in bytes
      size_t maxPlaintextLength{0}; // in bytes
      bool isPrivateKey{false};

      bool operator==(const AlgorithmInfo&) const = default;
   };

   Algorithm algorithm() const;
   AlgorithmInfo info() const;

public:
   /*!
   @brief Creates an asymmetric cipher object from key data.
   @param alg asymmetric cipher algorithm
   @param keyData public/private key data
   @return The cipher if successful, otherwise an error.
   */
   static std::expected<AsymmetricCipher, Error> create(Algorithm alg,
                                                        BytesView keyData);

   /*!
   @brief Creates an asymmetric cipher object from a key file.
   @param alg asymmetric cipher algorithm
   @param keyFilepath path to file containing public/private key data
   @return The cipher if successful, otherwise an error.
   */
   static std::expected<AsymmetricCipher, Error> create(
      Algorithm alg, const std::filesystem::path& keyFilepath);

   /*!
   @brief Creates an asymmetric cipher object using a generated key.
   @param alg asymmetric cipher algorithm
   @param keyLength length of key to generate in bytes
   @return The cipher if successful, otherwise an error.
   */
   static std::expected<AsymmetricCipher, Error> create(Algorithm alg,
                                                        size_t keyLength);

   /*!
   @brief Performs an encryption operation.
   @param plaintext unencrypted data
   @return The encrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> encrypt(BytesView plaintext);

   /*!
   @brief Performs a decryption operation.
   @param ciphertext encrypted data
   @return The decrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> decrypt(BytesView ciphertext);

public:
   ~AsymmetricCipher();
   AsymmetricCipher(AsymmetricCipher&&)            = default;
   AsymmetricCipher& operator=(AsymmetricCipher&&) = default;

private:
   AsymmetricCipher() = default;

   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
