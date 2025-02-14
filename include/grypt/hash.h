#ifndef GRYPT_HASH_H
#define GRYPT_HASH_H

#include <expected>
#include <filesystem>
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
   enum class Algorithm
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

   struct AlgorithmInfo
   {
      size_t digestLength{0};

      bool operator==(const AlgorithmInfo&) const = default;
   };

   Algorithm algorithm() const;
   AlgorithmInfo info() const;

public:
   /*!
   @brief Creates an hash object from key data.
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
