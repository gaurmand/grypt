#ifndef GRYPT_OSSLUTIL_H
#define GRYPT_OSSLUTIL_H

#include <expected>
#include <grypt/algorithm.h>
#include <grypt/error.h>
#include <iostream>
#include <memory>
#include <openssl/evp.h>

namespace grypt
{

template <class... Ts>
struct make_visitor : Ts...
{
   using Ts::operator()...;
};

} // namespace grypt

namespace grypt::ossl
{

// Bad! decltype(lambda) resolves to different types in different translation
// units. template <typename T, auto Deleter> using unique_ptr =
// std::unique_ptr<T, decltype([](T* obj) { Deleter(obj); })>;

struct evp_cipher_deleter
{
   void operator()(EVP_CIPHER* obj) { EVP_CIPHER_free(obj); }
};
using evp_cipher_ptr = std::unique_ptr<EVP_CIPHER, evp_cipher_deleter>;

struct evp_cipher_ctx_deleter
{
   void operator()(EVP_CIPHER_CTX* obj) { EVP_CIPHER_CTX_free(obj); }
};
using evp_cipher_ctx_ptr =
   std::unique_ptr<EVP_CIPHER_CTX, evp_cipher_ctx_deleter>;

std::expected<evp_cipher_ptr, Error> getCipher(SymmetricCipherAlgorithm alg);
std::expected<evp_cipher_ptr, Error> getCipher(
   AuthSymmetricCipherAlgorithm alg);

std::expected<evp_cipher_ctx_ptr, Error> makeCipherContext();
std::expected<void, Error> resetCipherContext(evp_cipher_ctx_ptr& ctx);

std::expected<AlgorithmInfo, Error> getInfo(const evp_cipher_ptr& cipher);

std::string handleError();

} // namespace grypt::ossl

#endif
