#ifndef GRYPT_ENCRYPTION_H
#define GRYPT_ENCRYPTION_H

#include <expected>
#include <memory>
#include <string>

namespace grypt
{

class Encryption
{
public:
   using Error  = std::string;
   using Result = std::expected<std::string, Error>;

public:
   Encryption(std::string key);
   ~Encryption();

   Result encrypt(std::string_view plaintext);
   Result decrypt(std::string_view ciphertext);

private:
   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
