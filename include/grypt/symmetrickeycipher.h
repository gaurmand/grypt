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

class SymmetricKeyCipher
{
public:
   static std::expected<SymmetricKeyCipher, Error> create(
      Bytes key, SymmetricCipherAlgorithm alg);

   virtual ~SymmetricKeyCipher();
   SymmetricKeyCipher(SymmetricKeyCipher&&)            = default;
   SymmetricKeyCipher& operator=(SymmetricKeyCipher&&) = default;

   SymmetricCipherAlgorithm getAlgorithm() const;
   AlgorithmInfo getAlgorithmInfo() const;

   // High level encrypt/decrypt operations
   std::expected<Bytes, Error> encrypt(BytesView plaintext, BytesView iv);
   std::expected<Bytes, Error> decrypt(BytesView ciphertext, BytesView iv);

   // Low level encrypt/decrypt operations
   std::expected<void, Error> encryptInit(BytesView iv);
   std::expected<Bytes, Error> encryptUpdate(BytesView plaintext);
   std::expected<Bytes, Error> encryptFinal();

   std::expected<void, Error> decryptInit(BytesView iv);
   std::expected<Bytes, Error> decryptUpdate(BytesView ciphertext);
   std::expected<Bytes, Error> decryptFinal();

   std::expected<void, Error> reset();

private:
   struct Data;
   std::unique_ptr<Data> d_;

   SymmetricKeyCipher();
};

} // namespace grypt

#endif
