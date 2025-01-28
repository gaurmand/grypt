#include <grypt/encryption.h>

namespace grypt
{

struct Encryption::Data
{
   std::string key;
};

Encryption::Encryption(std::string key)
   : d_(std::make_unique<Encryption::Data>(std::move(key)))
{
}

Encryption::~Encryption() = default;

Encryption::Result Encryption::encrypt(std::string_view plaintext)
{
   return std::string{plaintext};
}

Encryption::Result Encryption::decrypt(std::string_view ciphertext)
{
   return std::string{ciphertext};
}

} // namespace grypt
