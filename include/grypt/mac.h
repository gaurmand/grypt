#ifndef GRYPT_MAC_H
#define GRYPT_MAC_H

#include <expected>
#include <grypt/algorithm.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <memory>

namespace grypt
{

/*!
   @brief A MAC takes input data of arbitrary size and generates an
   authentication tag. This tag is used to enusre the integrity of the data.
*/
class MAC final
{
public:
   using Algorithm = MACAlgorithm;

   struct AlgorithmInfo
   {
      size_t tagLength{0};

      bool operator==(const AlgorithmInfo&) const = default;
   };

   Algorithm algorithm() const;
   AlgorithmInfo info() const;

public:
   /*!
   @brief Creates a MAC object that uses the HMAC algorithm.
   @param key key to use for the keyed hash function
   @param halg hash algorithm to use
   @return The MAC if successful, otherwise an error.
   */
   static std::expected<MAC, Error> createHMAC(Bytes key, HashAlgorithm halg);

   /*!
   @brief Creates a MAC object that uses the CMAC algorithm.
   @param key key to use for the cipher
   @param calg CBC cipher to use
   @return The MAC if successful, otherwise an error.
   */
   static std::expected<MAC, Error> createCMAC(Bytes key, CMACAlgorithm calg);

   /*!
   @brief Creates a MAC object that uses the GMAC algorithm.
   @param key key to use for the cipher
   @param calg GCM cipher to use
   @return The MAC if successful, otherwise an error.
   */
   static std::expected<MAC, Error> createGMAC(Bytes key,
                                               Bytes iv,
                                               GMACAlgorithm salg);

   /*!
   @brief Creates a MAC object.
   @note This factory function should only be used for non HMAC, CMAC, GMAC
   algorithms.
   @param key key to use for the MAC
   @param alg MAC algorithm to use
   @return The MAC if successful, otherwise an error.
   */
   static std::expected<MAC, Error> create(Bytes key, MACAlgorithm alg);

   /*!
   @brief Performs a sign operation.
   @param data data to sign
   @return The tag if successful, otherwise an error.
   */
   std::expected<Bytes, Error> sign(BytesView data);

   /*!
   @brief Performs a verify operation.
   @param data data to verify
   @param tag tag associated with the data
   @return The authenthication result if successful, otherwise an error.
   */
   std::expected<bool, Error> verify(BytesView data, BytesView tag);

public:
   /*!
   @brief Starts a MAC operation.
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> macInit();

   /*!
   @brief Adds data to the input. Must be called after init().
   @note May be called multiple times.
   @param data data to sign
   @return Nothing if successful, otherwise an error.
   */
   std::expected<void, Error> macUpdate(BytesView data);

   /*!
   @brief Generates the tag. Must be called after update(). Ends
   the MAC operation.
   @return The tag if successful, otherwise an error.
   */
   std::expected<Bytes, Error> macFinal();

public:
   ~MAC();
   MAC(MAC&&)            = default;
   MAC& operator=(MAC&&) = default;

private:
   MAC() = default;

   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
