#include <grypt/error.h>
#include <string>

namespace grypt
{
namespace
{

using namespace std::literals;

struct ErrorCategory : std::error_category
{
   const char* name() const noexcept override { return "grpyt"; }
   std::string message(int cond) const override
   {
      switch (static_cast<ErrorCode>(cond))
      {
         case ErrorCode::InvalidKeyLength:
         case ErrorCode::InvalidIVLength:
         case ErrorCode::RandomBytesFailure:
         case ErrorCode::EncryptionFailure:
         case ErrorCode::DecryptionFailure:
         default: return "Unknown error";
      }
   }
};

} // namespace

std::error_code make_error_code(ErrorCode err)
{
   static ErrorCategory kErrorCategory;
   return {static_cast<int>(err), kErrorCategory};
}

} // namespace grypt
