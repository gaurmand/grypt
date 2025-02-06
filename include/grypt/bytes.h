#ifndef GRYPT_BYTES_H
#define GRYPT_BYTES_H

#include <compare>
#include <initializer_list>
#include <iostream>
#include <ranges>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace grypt
{

template <typename R>
concept ContiguousByteRange =
   std::ranges::contiguous_range<R> &&
   std::same_as<std::ranges::range_value_t<R>, std::byte>;

class BytesView : public std::span<const std::byte>
{
public:
   BytesView() = default;
   explicit BytesView(std::string_view str);

   template <ContiguousByteRange R>
   explicit BytesView(R&& range)
      : std::span<const std::byte>{std::forward<R>(range)}
   {
   }

   std::strong_ordering operator<=>(const BytesView& other) const;
   bool operator==(const BytesView& other) const;

   std::string toHex() const;

   const unsigned char* udata() const;
};

class Bytes : public std::vector<std::byte>
{
public:
   Bytes() = default;
   explicit Bytes(std::string_view str);
   explicit Bytes(std::initializer_list<std::byte> il);
   explicit Bytes(BytesView bv);
   operator BytesView() const;

   Bytes(size_t count, std::byte byte = std::byte{0});

   static Bytes fromHex(std::string_view hex);
   std::string toHex() const;

   const unsigned char* udata() const;
   unsigned char* udata();

   Bytes& operator+=(BytesView);
};

Bytes operator+(const BytesView&, const BytesView&);

std::ostream& operator<<(std::ostream& os, const BytesView& bv);
std::ostream& operator<<(std::ostream& os, const Bytes& b);
std::istream& operator>>(std::istream& is, Bytes& b);

namespace literals
{

BytesView operator""_bv(const char* c, size_t n);
Bytes operator""_b(const char* c, size_t n);

} // namespace literals

} // namespace grypt

// Make BytesView a borrowed range
template <>
inline constexpr bool std::ranges::enable_borrowed_range<grypt::BytesView> =
   true;

#endif
