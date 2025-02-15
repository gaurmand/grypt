#ifndef GRYPT_DIGITALSIGNATURE_H
#define GRYPT_DIGITALSIGNATURE_H

#include <expected>
#include <filesystem>
#include <grypt/algorithm.h>
#include <grypt/asymkey.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <memory>

namespace grypt
{

/*!
   @brief A cipher that performs encryption with a public key and decryption
   with a private key.
*/
class DigitalSignature final
{
public:
   using Algorithm = DigitalSignatureAlgorithm;

   struct AlgorithmInfo
   {
      size_t keyLength{0}; // in bits
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
   static std::expected<DigitalSignature, Error> create(Algorithm alg,
                                                        AsymKeyParam param,
                                                        HashAlgorithm halg);

   static std::expected<DigitalSignature, Error> createED(Algorithm alg,
                                                          AsymKeyParam param);

   static std::expected<DigitalSignature, Error> createRSA(
      AsymKeyParam param, RSAPadding pad, std::optional<HashAlgorithm> halg);

   /*!
   @brief Performs an encryption operation.
   @param plaintext unencrypted data
   @return The encrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> sign(BytesView data);

   /*!
   @brief Performs a decryption operation.
   @param ciphertext encrypted data
   @return The decrypted data if successful, otherwise an error.
   */
   std::expected<bool, Error> verify(BytesView data, BytesView tag);

public:
   /*!
   @brief Starts a MAC operation.
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> signInit();

   /*!
   @brief Adds data to the input. Must be called after init().
   @note May be called multiple times.
   @param data data to sign
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> signUpdate(BytesView data);

   /*!
   @brief Generates the tag. Must be called after update(). Ends
   the MAC operation.
   @return The tag if successful, otherwise an error.
   */
   std::expected<Bytes, Error> signFinal();

   /*!
   @brief Starts a MAC operation.
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> verifyInit();

   /*!
   @brief Adds data to the input. Must be called after init().
   @note May be called multiple times.
   @param data data to sign
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> verifyUpdate(BytesView data);

   /*!
   @brief Generates the tag. Must be called after update(). Ends
   the MAC operation.
   @return The tag if successful, otherwise an error.
   */
   std::expected<bool, Error> verifyFinal(BytesView tag);

public:
   ~DigitalSignature();
   DigitalSignature(DigitalSignature&&)            = default;
   DigitalSignature& operator=(DigitalSignature&&) = default;

private:
   DigitalSignature() = default;

   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
