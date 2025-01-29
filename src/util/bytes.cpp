#include <algorithm>
#include <cassert>
#include <charconv>
#include <grypt/bytes.h>
#include <iostream>
#include <iterator>
#include <ranges>

namespace grypt
{

namespace
{

using namespace std::literals;

template <typename ByteContainer>
std::string toHex(const ByteContainer& bytes)
{
   std::string hex;
   if (bytes.empty())
   {
      return hex;
   }

   hex.reserve(2 * bytes.size() + 2);
   hex.append("0x");

   for (std::byte byte : bytes)
   {
      std::array<char, 2> buf;
      auto [ptr, ec] = std::to_chars(
         buf.begin(), buf.end(), std::to_integer<unsigned char>(byte), 16);

      assert(ec == std::errc());
      if (ec != std::errc())
      {
         std::cout << std::make_error_code(ec).message() << '\n';
         hex.clear();
         break;
      }
      else
      {
         auto sz = std::distance(buf.begin(), ptr);
         assert(sz == 1 || sz == 2);

         // If only a single hex char generated, prepend with a '0'
         if (std::distance(buf.begin(), ptr) == 1)
         {
            hex.push_back('0');
         }
         hex.append(buf.begin(), ptr);
      }
   }

   return hex;
}

template <typename ByteContainer>
ByteContainer fromHex(std::string_view hex)
{
   ByteContainer bytes;

   if (hex.starts_with("0x") || hex.starts_with("0X"))
   {
      hex.remove_prefix(2);
   }
   if (hex.empty())
   {
      return bytes;
   }

   // If odd number of hex chars, make a view prefixed with 0 to make
   // processing easier.
   std::array<std::string_view, 2> hexParts;
   hexParts[0] = (hex.size() % 2 == 0) ? ""sv : "0"sv;
   hexParts[1] = hex;

   bytes.reserve(hex.size() / 2);
   for (auto word : std::views::join(hexParts) | std::views::chunk(2))
   {
      assert(std::ranges::distance(word.begin(), word.end()) == 2);

      std::array<char, 2> buf;
      std::ranges::copy(word, buf.begin());

      unsigned char val{0};
      auto [_, ec] = std::from_chars(buf.cbegin(), buf.cend(), val, 16);
      if (ec != std::errc())
      {
         // std::cout << std::make_error_code(ec).message() << '\n';
         bytes.clear();
         break;
      }
      else
      {
         bytes.push_back(std::byte{val});
      }
   }

   return bytes;
}

} // namespace

BytesView::BytesView(std::string_view str)
   : std::span<const std::byte>(std::as_bytes(std::span{str}))
{
}

std::strong_ordering BytesView::operator<=>(const BytesView& other) const
{
   return std::lexicographical_compare_three_way(
      cbegin(), cend(), other.cbegin(), other.end());
}

bool BytesView::operator==(const BytesView& other) const
{
   return std::ranges::equal(*this, other);
}

std::string BytesView::toHex() const
{
   return grypt::toHex(*this);
}

const unsigned char* BytesView::udata() const
{
   return reinterpret_cast<const unsigned char*>(data());
}

Bytes::Bytes(std::string_view str) : std::vector<std::byte>(str.size())
{
   std::ranges::transform(
      str, begin(), [](char ch) { return static_cast<std::byte>(ch); });
}

Bytes::Bytes(std::initializer_list<std::byte> il) : std::vector<std::byte>{il}
{
}

Bytes::Bytes(BytesView bv) : std::vector<std::byte>(bv.size())
{
   std::ranges::copy(bv, begin());
}

Bytes::operator BytesView() const
{
   return BytesView{*this};
}

Bytes::Bytes(size_t count, std::byte byte) : std::vector<std::byte>(count, byte)
{
}

std::string Bytes::toHex() const
{
   return grypt::toHex(*this);
}

Bytes Bytes::fromHex(std::string_view hex)
{
   return grypt::fromHex<Bytes>(hex);
}

const unsigned char* Bytes::udata() const
{
   return reinterpret_cast<const unsigned char*>(data());
}

unsigned char* Bytes::udata()
{
   return reinterpret_cast<unsigned char*>(data());
}

Bytes& Bytes::operator+=(BytesView other)
{
   size_t oldSize = size();
   resize(oldSize + other.size());
   std::ranges::copy(other, begin() + oldSize);
   return *this;
}

Bytes operator+(const BytesView& lhs, const BytesView& rhs)
{
   Bytes temp{lhs};
   temp += rhs;
   return temp;
}

std::ostream& operator<<(std::ostream& os, const BytesView& bv)
{
   return os << bv.toHex();
}

std::ostream& operator<<(std::ostream& os, const Bytes& b)
{
   return os << b.toHex();
}

std::istream& operator>>(std::istream& is, Bytes& b)
{
   std::string buf;
   is >> buf;
   b = Bytes::fromHex(buf);
   return is;
}

namespace literals
{

BytesView operator""_bv(const char* c, size_t n)
{
   std::string_view str{c, n};
   return BytesView{str};
}

Bytes operator""_b(const char* c, size_t n)
{
   std::string_view str{c, n};
   return Bytes{str};
}

} // namespace literals

} // namespace grypt
