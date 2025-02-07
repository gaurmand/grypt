#ifndef GRYPT_SYMMETRICKEYCIPHER_H
#define GRYPT_SYMMETRICKEYCIPHER_H

#include <expected>
#include <grypt/algorithm.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <memory>
#include <optional>
#include <string>

namespace grypt
{

/*!
   @brief A cipher that performs encryption/decryption with the same key.
*/
class SymmetricCipher final
{
public:
   /*!
   @brief Creates a symmetric cipher object.
   @param key key to use for encrypt/decrypt
   @param alg symmetric cipher algorithm to use
   @return The cipher if successful, otherwise an error.
   */
   static std::expected<SymmetricCipher, Error> create(
      Bytes key, SymmetricCipherAlgorithm alg);

   /*!
   @brief Performs a full encryption operation.
   @param plaintext unencrypted data
   @param iv initialization vector
   @return The encrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> encrypt(BytesView plaintext, BytesView iv);

   /*!
   @brief Performs a full decryption operation.
   @param ciphertext encrypted data
   @param iv initialization vector
   @return The decrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> decrypt(BytesView ciphertext, BytesView iv);

public:
   /*!
   @brief Starts the encryption operation.
   @param iv initialization vector
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> encryptInit(BytesView iv);

   /*!
   @brief Encrypts the given data. Must be called init().
   @note May be called multiple times to encrypt successive blocks of data (not
   supported by some algorithms).
   @param plaintext unencrypted data
   @return The encrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> encryptUpdate(BytesView plaintext);

   /*!
   @brief Encrypts the last block of data. Must be called after update(). Ends
   the encryption operation.
   @return The final block of encrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> encryptFinal();

   /*!
   @brief Starts the decryption operation.
   @param iv initialization vector
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> decryptInit(BytesView iv);

   /*!
   @brief Decrypts the given data. Must be called after init().
      @note May be called multiple times to decrypt successive blocks of data
   (not supported by some algorithms).
   @param ciphertext encrypted data
   @return The decrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> decryptUpdate(BytesView ciphertext);

   /*!
   @brief Decrypts the last block of data. Must be called after update(). Ends
   the decryption operation.
   @return The final block of decrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> decryptFinal();

public:
   ~SymmetricCipher();
   SymmetricCipher(SymmetricCipher&&)            = default;
   SymmetricCipher& operator=(SymmetricCipher&&) = default;

   SymmetricCipherAlgorithm getAlgorithm() const;
   AlgorithmInfo getAlgorithmInfo() const;

private:
   SymmetricCipher() = default;

   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
