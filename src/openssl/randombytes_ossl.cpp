#include "osslutil.h"

#include <cassert>
#include <grypt/randombytes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

namespace grypt
{

std::expected<Bytes, Error> generateRandomBytes(size_t sz)
{
   Bytes bytes(sz);
   if (bytes.size() == 0)
   {
      return bytes;
   }

   auto res = RAND_bytes(bytes.udata(), bytes.size());
   if (res != ERR_LIB_NONE)
   {
      ossl::handleError();
      return std::unexpected{ErrorCode::RandomBytesFailure};
   }

   return bytes;
}

} // namespace grypt
