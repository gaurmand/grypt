#ifndef GRYPT_OSSLUTIL_H
#define GRYPT_OSSLUTIL_H

#include <expected>
#include <grypt/algorithm.h>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <iostream>
#include <memory>
#include <openssl/decoder.h>
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

std::string_view toString(SymmetricCipherAlgorithm alg);
std::string_view toString(AuthSymmetricCipherAlgorithm alg);
std::string_view toString(HashAlgorithm alg);
std::string_view toString(MACAlgorithm alg);
std::string_view toString(CMACAlgorithm alg);
std::string_view toString(GMACAlgorithm alg);

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

std::expected<evp_cipher_ctx_ptr, Error> makeCipherContext(
   const evp_cipher_ptr& cipher);
std::expected<void, Error> resetCipherContext(evp_cipher_ctx_ptr& ctx);

std::expected<AlgorithmInfo, Error> getInfo(const evp_cipher_ptr& cipher);
std::string handleError();

struct evp_pkey_deleter
{
   void operator()(EVP_PKEY* obj) { EVP_PKEY_free(obj); }
};
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;

struct evp_pkey_ctx_deleter
{
   void operator()(EVP_PKEY_CTX* obj) { EVP_PKEY_CTX_free(obj); }
};
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;

struct decoder_ctx_deleter
{
   void operator()(OSSL_DECODER_CTX* obj) { OSSL_DECODER_CTX_free(obj); }
};
using decoder_ctx_ptr = std::unique_ptr<OSSL_DECODER_CTX, decoder_ctx_deleter>;

struct evp_md_deleter
{
   void operator()(EVP_MD* obj) { EVP_MD_free(obj); }
};
using evp_md_ptr = std::unique_ptr<EVP_MD, evp_md_deleter>;

struct evp_md_ctx_deleter
{
   void operator()(EVP_MD_CTX* obj) { EVP_MD_CTX_free(obj); }
};
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, evp_md_ctx_deleter>;

struct evp_mac_deleter
{
   void operator()(EVP_MAC* obj) { EVP_MAC_free(obj); }
};
using evp_mac_ptr = std::unique_ptr<EVP_MAC, evp_mac_deleter>;

struct evp_mac_ctx_deleter
{
   void operator()(EVP_MAC_CTX* obj) { EVP_MAC_CTX_free(obj); }
};
using evp_mac_ctx_ptr = std::unique_ptr<EVP_MAC_CTX, evp_mac_ctx_deleter>;

} // namespace grypt::ossl

#endif
