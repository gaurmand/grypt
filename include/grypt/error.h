#ifndef GRYPT_ERROR_H
#define GRYPT_ERROR_H

#include <string>
#include <system_error>

namespace grypt
{

enum class ErrorCode
{
   InvalidArguments,
   InitializeCipherFailed,
   FetchCipherDataFailed,
   InvalidPlaintextLength,
   InvalidKeyLength,
   InvalidIVLength,
   InvalidTagLength,
   RandomBytesFailure,
   EncryptionFailure,
   DecryptionFailure,
   EncryptUpdateNotAllowed,
   DecryptUpdateNotAllowed,
   EncryptAADNotAllowed,
   DecryptAADNotAllowed,
   EncryptFinalNotAllowed,
   DecryptFinalNotAllowed,
   EncryptTagNotAllowed,
   DecryptTagNotAllowed,
   KeyGenerationFailure,
   KeyParseFailure,
   PublicKeyDecryptFailure,
   PublicKeySignFailure,
   DigestFailure,
   DigestUpdateNotAllowed,
   DigestFinalNotAllowed,
   MACFailure,
   MACUpdateNotAllowed,
   MACFinalNotAllowed,
   DSSignFailed,
   DSVerifyFailed,
   SignUpdateNotAllowed,
   SignFinalNotAllowed,
   VerifyUpdateNotAllowed,
   VerifyFinalNotAllowed
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
