#include "../symmetric_encryption.h"

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace grypt
{

void f()
{
   EVP_CIPHER_CTX* ctx;
   if (!(ctx = EVP_CIPHER_CTX_new())) {}
}

} // namespace grypt
