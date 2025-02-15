#ifndef GRYPT_HASH_H
#define GRYPT_HASH_H

#include <expected>
#include <filesystem>
#include <grypt/algorithm.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <memory>

namespace grypt
{

/*!
   @brief A hash takes input data of arbitrary length and outputs a fixed size
   digest.
*/
class Hash final
{
public:
   using Algorithm = HashAlgorithm;

   struct AlgorithmInfo
   {
      size_t digestLength{0};

      bool operator==(const AlgorithmInfo&) const = default;
   };

   Algorithm algorithm() const;
   AlgorithmInfo info() const;

public:
   /*!
   @brief Creates a hash object.
   @param alg hash algorithm
   @return The hash if successful, otherwise an error.
   */
   static std::expected<Hash, Error> create(Algorithm alg);

   /*!
   @brief Performs a digest operation.
   @param data data to hash
   @return The digest if successful, otherwise an error.
   */
   std::expected<Bytes, Error> digest(BytesView data);

public:
   /*!
   @brief Starts the digest operation.
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> digestInit();

   /*!
   @brief Hashes the given data. Must be called after init().
   @note May be called multiple times to hash additional data.
   @param data data to hash
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> digestUpdate(BytesView data);

   /*!
   @brief Returns the digest. Must be called after update(). Ends
   the digest operation.
   @return The digest if successful, otherwise an error.
   */
   std::expected<Bytes, Error> digestFinal();

public:
   ~Hash();
   Hash(Hash&&)            = default;
   Hash& operator=(Hash&&) = default;

private:
   Hash() = default;

   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
