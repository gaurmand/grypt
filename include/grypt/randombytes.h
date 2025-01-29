#ifndef GRYPT_RANDOMBYTES_H
#define GRYPT_RANDOMBYTES_H

#include <expected>
#include <grypt/bytes.h>
#include <grypt/error.h>
#include <memory>
#include <optional>
#include <string>

namespace grypt
{

std::expected<Bytes, Error> generateRandomBytes(size_t sz);

} // namespace grypt

#endif
