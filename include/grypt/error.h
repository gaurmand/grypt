#ifndef GRYPT_ERROR_H
#define GRYPT_ERROR_H

#include <string>
#include <system_error>

namespace grypt
{

enum class ErrorCode
{
   FetchCipherFailed,
   FetchCipherParamsFailed,
   CreateCipherContextFailed,
   ResetCipherContextFailed,
   InvalidKeyLength,
   InvalidIVLength,
   RandomBytesFailure,
   EncryptionFailure,
   DecryptionFailure,
   EncryptUpdateNotAllowed,
   DecryptUpdateNotAllowed,
   EncryptFinalNotAllowed,
   DecryptFinalNotAllowed
};

std::error_code make_error_code(ErrorCode);

using Error = std::error_code;

} // namespace grypt

namespace std
{

template <>
struct is_error_code_enum<grypt::ErrorCode> : true_type
{
};

} // namespace std

#endif
