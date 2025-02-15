#ifndef GRYPT_ASYMKEY_H
#define GRYPT_ASYMKEY_H

#include <filesystem>
#include <grypt/bytes.h>
#include <variant>

namespace grypt
{

using AsymKeyParam = std::variant<BytesView, std::filesystem::path>;

} // namespace grypt

#endif
