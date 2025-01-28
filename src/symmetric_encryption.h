#ifndef GRYPT_SYMMETRIC_ENCRYPTION_H
#define GRYPT_SYMMETRIC_ENCRYPTION_H

#include <expected>
#include <memory>
#include <string>

namespace grypt
{

void f();

class SymmetricEncryption
{
public:
   using Error  = std::string;
   using Result = std::expected<std::string, Error>;

public:
   SymmetricEncryption(std::string key);
   ~SymmetricEncryption();

   Result encrypt(std::string_view plaintext);
   Result decrypt(std::string_view ciphertext);

private:
   struct Data;
   std::unique_ptr<Data> d_;
};

} // namespace grypt

#endif
