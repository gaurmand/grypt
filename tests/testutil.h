#ifndef GRYPT_TEST_UTIL_H
#define GRYPT_TEST_UTIL_H

#include <grypt/algorithm.h>
#include <grypt/bytes.h>

namespace grypt
{

using namespace grypt::literals;

inline const auto kTestKey = Bytes::fromHex(
   "0x6d448552e4d9aeb6ee76785cad9a143f978dcc423e8e1f92201776e6fa5d6b5a7af825bdf"
   "d6fc768153101325fafff8e8a75117bfe936e2313651755efaeeb97");

inline const auto kTestPlaintext = "Sphinx of black quartz, judge my vow"_bv;
const auto kTestWrapPlaintext    = "This string is a multiple of 8!?"_bv;
inline const auto kTestAAD =
   "Non confidential data that must be authenticated"_bv;

inline const auto kTestIV1 =
   Bytes::fromHex("0x306ed3c7f141f8df95836e2875663e82");
inline const auto kTestIV2 =
   Bytes::fromHex("0x7121a4f474186c1e5355fc1d3c24e380");

// For gtest i/o
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
