#ifndef GRYPT_TEST_UTIL_H
#define GRYPT_TEST_UTIL_H

#include <grypt/algorithm.h>
#include <grypt/bytes.h>

namespace grypt
{

inline void PrintTo(const BytesView& bv, std::ostream* os)
{
   *os << bv;
}

inline void PrintTo(const Bytes& b, std::ostream* os)
{
   *os << b;
}

inline void PrintTo(const AlgorithmInfo& info, std::ostream* os)
{
   *os << "{" << info.keyLength << ", " << info.ivLength << ", "
       << info.blockSize << ", " << static_cast<int>(info.mode) << "}";
}

} // namespace grypt

#endif
