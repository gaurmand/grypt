#ifndef GRYPT_AUTHSYMMETRICKEYCIPHER_H
#define GRYPT_AUTHSYMMETRICKEYCIPHER_H

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
   @brief A cipher that performs authenticated encryption/decryption with the
   same key.
*/
class AuthSymmetricCipher final
{
public:
   /*!
   @brief Creates an authenticated symmetric cipher object.
   @param key key to use for encrypt/decrypt
   @param alg symmetric cipher algorithm to use
   @return The cipher if successful, otherwise an error.
   */
   static std::expected<AuthSymmetricCipher, Error> create(
      Bytes key, AuthSymmetricCipherAlgorithm alg);

public:
   struct EncryptionResult
   {
      Bytes ciphertext;
      Bytes tag;
   };

   /*!
   @brief Performs an entire authenticated encryption operation.
   @param plaintext unencrypted data
   @param iv initialization vector
   @param aad additional authenticated data
   @return The encrypted data and authentication tag if successful, otherwise an
   error.
   */
   std::expected<EncryptionResult, Error> encrypt(
      BytesView plaintext,
      BytesView iv,
      std::optional<BytesView> aad = std::nullopt);

   /*!
   @brief Performs an entire authenticated decryption operation.
   @param plaintext unencrypted data
   @param iv initialization vector
   @param tag authentication tag
   @param aad additional authenticated data
   @return The decrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> decrypt(
      BytesView ciphertext,
      BytesView iv,
      BytesView tag,
      std::optional<BytesView> aad = std::nullopt);

public:
   /*!
   @brief Starts the encryption operation.
   @param iv initialization vector
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> encryptInit(BytesView iv);

   /*!
   @brief Sets additional data to authenticate (optional). Must be called after
   init(), and before update().
   @note May be called multiple times (not supported some algorithms).
   @param aad additional authenticated data
   @param ptlen plaintext length (only necessary for CCM)
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> encryptAAD(
      BytesView aad, std::optional<size_t> ptlen = std::nullopt);

   /*!
   @brief Encrypts the given data. Must be called after init().
   @note May be called multiple times to encrypt successive blocks of data (not
   supported some algorithms).
   @param plaintext unencrypted data
   @return The encrypted data if successful, otherwise an error.
   */
   std::expected<Bytes, Error> encryptUpdate(BytesView plaintext);

   /*!
   @brief Encrypts the last block of data. Must be called after update(). Ends
   the encryption operation.
   @return The final block of encrypted data and authentication tag if
   successful, otherwise an error.
   */
   std::expected<EncryptionResult, Error> encryptFinal();

   /*!
   @brief Starts the decryption operation.
   @param iv initialization vector
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> decryptInit(BytesView iv, BytesView tag);

   /*!
   @brief Sets additional data to authenticate (optional). Must be called after
   init() and before update().
   @note May be called multiple times (not supported by some algorithms).
   @param aad additional authenticated data
   @param ctlen ciphertext length (only necessary for CCM)
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> decryptAAD(
      BytesView aad, std::optional<size_t> ctlen = std::nullopt);

   /*!
   @brief Decrypts the given data. Must be called after init().
   @note  May be called multiple times to decrypt successive blocks of data (not
   supported by some algorithms).
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
   ~AuthSymmetricCipher();
   AuthSymmetricCipher(AuthSymmetricCipher&&)            = default;
   AuthSymmetricCipher& operator=(AuthSymmetricCipher&&) = default;

   AuthSymmetricCipherAlgorithm getAlgorithm() const;
   AlgorithmInfo getAlgorithmInfo() const;

private:
   AuthSymmetricCipher() = default;

   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
