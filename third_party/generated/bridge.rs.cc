#include "ffi/certificates_ffi.h"
#include "ffi/credentials_ffi.h"
#include "ffi/server_tls_ffi.h"
#include "ffi/client_tls_ffi.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#if __cplusplus >= 201703L
#include <string_view>
#endif
#if __cplusplus >= 202002L
#include <ranges>
#endif

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wshadow"
#ifdef __clang__
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#endif // __clang__
#endif // __GNUC__

namespace rust {
inline namespace cxxbridge1 {
// #include "rust/cxx.h"

#ifndef CXXBRIDGE1_PANIC
#define CXXBRIDGE1_PANIC
template <typename Exception>
void panic [[noreturn]] (const char *msg);
#endif // CXXBRIDGE1_PANIC

struct unsafe_bitcopy_t;

namespace {
template <typename T>
class impl;
} // namespace

template <typename T>
::std::size_t size_of();
template <typename T>
::std::size_t align_of();

#ifndef CXXBRIDGE1_RUST_STRING
#define CXXBRIDGE1_RUST_STRING
class String final {
public:
  String() noexcept;
  String(const String &) noexcept;
  String(String &&) noexcept;
  ~String() noexcept;

  String(const std::string &);
  String(const char *);
  String(const char *, std::size_t);
  String(const char16_t *);
  String(const char16_t *, std::size_t);
#ifdef __cpp_char8_t
  String(const char8_t *s);
  String(const char8_t *s, std::size_t len);
#endif

  static String lossy(const std::string &) noexcept;
  static String lossy(const char *) noexcept;
  static String lossy(const char *, std::size_t) noexcept;
  static String lossy(const char16_t *) noexcept;
  static String lossy(const char16_t *, std::size_t) noexcept;

  String &operator=(const String &) & noexcept;
  String &operator=(String &&) & noexcept;

  explicit operator std::string() const;

  const char *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;
  bool empty() const noexcept;

  const char *c_str() noexcept;

  std::size_t capacity() const noexcept;
  void reserve(size_t new_cap) noexcept;

  using iterator = char *;
  iterator begin() noexcept;
  iterator end() noexcept;

  using const_iterator = const char *;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  bool operator==(const String &) const noexcept;
  bool operator!=(const String &) const noexcept;
  bool operator<(const String &) const noexcept;
  bool operator<=(const String &) const noexcept;
  bool operator>(const String &) const noexcept;
  bool operator>=(const String &) const noexcept;

  void swap(String &) noexcept;

  String(unsafe_bitcopy_t, const String &) noexcept;

private:
  struct lossy_t;
  String(lossy_t, const char *, std::size_t) noexcept;
  String(lossy_t, const char16_t *, std::size_t) noexcept;
  friend void swap(String &lhs, String &rhs) noexcept { lhs.swap(rhs); }

  std::array<std::uintptr_t, 3> repr;
};
#endif // CXXBRIDGE1_RUST_STRING

#ifndef CXXBRIDGE1_RUST_STR
#define CXXBRIDGE1_RUST_STR
class Str final {
public:
  Str() noexcept;
  Str(const String &) noexcept;
  Str(const std::string &);
  Str(const char *);
  Str(const char *, std::size_t);

  Str &operator=(const Str &) & noexcept = default;

  explicit operator std::string() const;
#if __cplusplus >= 201703L
  explicit operator std::string_view() const;
#endif

  const char *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;
  bool empty() const noexcept;

  Str(const Str &) noexcept = default;
  ~Str() noexcept = default;

  using iterator = const char *;
  using const_iterator = const char *;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  bool operator==(const Str &) const noexcept;
  bool operator!=(const Str &) const noexcept;
  bool operator<(const Str &) const noexcept;
  bool operator<=(const Str &) const noexcept;
  bool operator>(const Str &) const noexcept;
  bool operator>=(const Str &) const noexcept;

  void swap(Str &) noexcept;

private:
  class uninit;
  Str(uninit) noexcept;
  friend impl<Str>;

  std::array<std::uintptr_t, 2> repr;
};
#endif // CXXBRIDGE1_RUST_STR

#ifndef CXXBRIDGE1_RUST_SLICE
#define CXXBRIDGE1_RUST_SLICE
namespace detail {
template <bool>
struct copy_assignable_if {};

template <>
struct copy_assignable_if<false> {
  copy_assignable_if() noexcept = default;
  copy_assignable_if(const copy_assignable_if &) noexcept = default;
  copy_assignable_if &operator=(const copy_assignable_if &) & noexcept = delete;
  copy_assignable_if &operator=(copy_assignable_if &&) & noexcept = default;
};
} // namespace detail

template <typename T>
class Slice final
    : private detail::copy_assignable_if<std::is_const<T>::value> {
public:
  using value_type = T;

  Slice() noexcept;
  Slice(T *, std::size_t count) noexcept;

  template <typename C>
  explicit Slice(C &c) : Slice(c.data(), c.size()) {}

  Slice &operator=(const Slice<T> &) & noexcept = default;
  Slice &operator=(Slice<T> &&) & noexcept = default;

  T *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;
  bool empty() const noexcept;

  T &operator[](std::size_t n) const noexcept;
  T &at(std::size_t n) const;
  T &front() const noexcept;
  T &back() const noexcept;

  Slice(const Slice<T> &) noexcept = default;
  ~Slice() noexcept = default;

  class iterator;
  iterator begin() const noexcept;
  iterator end() const noexcept;

  void swap(Slice &) noexcept;

private:
  class uninit;
  Slice(uninit) noexcept;
  friend impl<Slice>;
  friend void sliceInit(void *, const void *, std::size_t) noexcept;
  friend void *slicePtr(const void *) noexcept;
  friend std::size_t sliceLen(const void *) noexcept;

  std::array<std::uintptr_t, 2> repr;
};

#ifdef __cpp_deduction_guides
template <typename C>
explicit Slice(C &c)
    -> Slice<std::remove_reference_t<decltype(*std::declval<C>().data())>>;
#endif // __cpp_deduction_guides

template <typename T>
class Slice<T>::iterator final {
public:
#if __cplusplus >= 202002L
  using iterator_category = std::contiguous_iterator_tag;
#else
  using iterator_category = std::random_access_iterator_tag;
#endif
  using value_type = T;
  using difference_type = std::ptrdiff_t;
  using pointer = typename std::add_pointer<T>::type;
  using reference = typename std::add_lvalue_reference<T>::type;

  reference operator*() const noexcept;
  pointer operator->() const noexcept;
  reference operator[](difference_type) const noexcept;

  iterator &operator++() noexcept;
  iterator operator++(int) noexcept;
  iterator &operator--() noexcept;
  iterator operator--(int) noexcept;

  iterator &operator+=(difference_type) noexcept;
  iterator &operator-=(difference_type) noexcept;
  iterator operator+(difference_type) const noexcept;
  friend inline iterator operator+(difference_type lhs, iterator rhs) noexcept {
    return rhs + lhs;
  }
  iterator operator-(difference_type) const noexcept;
  difference_type operator-(const iterator &) const noexcept;

  bool operator==(const iterator &) const noexcept;
  bool operator!=(const iterator &) const noexcept;
  bool operator<(const iterator &) const noexcept;
  bool operator<=(const iterator &) const noexcept;
  bool operator>(const iterator &) const noexcept;
  bool operator>=(const iterator &) const noexcept;

private:
  friend class Slice;
  void *pos;
  std::size_t stride;
};

#if __cplusplus >= 202002L
static_assert(std::ranges::contiguous_range<rust::Slice<const uint8_t>>);
static_assert(std::contiguous_iterator<rust::Slice<const uint8_t>::iterator>);
#endif

template <typename T>
Slice<T>::Slice() noexcept {
  sliceInit(this, reinterpret_cast<void *>(align_of<T>()), 0);
}

template <typename T>
Slice<T>::Slice(T *s, std::size_t count) noexcept {
  assert(s != nullptr || count == 0);
  sliceInit(this,
            s == nullptr && count == 0
                ? reinterpret_cast<void *>(align_of<T>())
                : const_cast<typename std::remove_const<T>::type *>(s),
            count);
}

template <typename T>
T *Slice<T>::data() const noexcept {
  return reinterpret_cast<T *>(slicePtr(this));
}

template <typename T>
std::size_t Slice<T>::size() const noexcept {
  return sliceLen(this);
}

template <typename T>
std::size_t Slice<T>::length() const noexcept {
  return this->size();
}

template <typename T>
bool Slice<T>::empty() const noexcept {
  return this->size() == 0;
}

template <typename T>
T &Slice<T>::operator[](std::size_t n) const noexcept {
  assert(n < this->size());
  auto ptr = static_cast<char *>(slicePtr(this)) + size_of<T>() * n;
  return *reinterpret_cast<T *>(ptr);
}

template <typename T>
T &Slice<T>::at(std::size_t n) const {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Slice index out of range");
  }
  return (*this)[n];
}

template <typename T>
T &Slice<T>::front() const noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
T &Slice<T>::back() const noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
typename Slice<T>::iterator::reference
Slice<T>::iterator::operator*() const noexcept {
  return *static_cast<T *>(this->pos);
}

template <typename T>
typename Slice<T>::iterator::pointer
Slice<T>::iterator::operator->() const noexcept {
  return static_cast<T *>(this->pos);
}

template <typename T>
typename Slice<T>::iterator::reference Slice<T>::iterator::operator[](
    typename Slice<T>::iterator::difference_type n) const noexcept {
  auto ptr = static_cast<char *>(this->pos) + this->stride * n;
  return *reinterpret_cast<T *>(ptr);
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator++() noexcept {
  this->pos = static_cast<char *>(this->pos) + this->stride;
  return *this;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator++(int) noexcept {
  auto ret = iterator(*this);
  this->pos = static_cast<char *>(this->pos) + this->stride;
  return ret;
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator--() noexcept {
  this->pos = static_cast<char *>(this->pos) - this->stride;
  return *this;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator--(int) noexcept {
  auto ret = iterator(*this);
  this->pos = static_cast<char *>(this->pos) - this->stride;
  return ret;
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator+=(
    typename Slice<T>::iterator::difference_type n) noexcept {
  this->pos = static_cast<char *>(this->pos) + this->stride * n;
  return *this;
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator-=(
    typename Slice<T>::iterator::difference_type n) noexcept {
  this->pos = static_cast<char *>(this->pos) - this->stride * n;
  return *this;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator+(
    typename Slice<T>::iterator::difference_type n) const noexcept {
  auto ret = iterator(*this);
  ret.pos = static_cast<char *>(this->pos) + this->stride * n;
  return ret;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator-(
    typename Slice<T>::iterator::difference_type n) const noexcept {
  auto ret = iterator(*this);
  ret.pos = static_cast<char *>(this->pos) - this->stride * n;
  return ret;
}

template <typename T>
typename Slice<T>::iterator::difference_type
Slice<T>::iterator::operator-(const iterator &other) const noexcept {
  auto diff = std::distance(static_cast<char *>(other.pos),
                            static_cast<char *>(this->pos));
  return diff / static_cast<typename Slice<T>::iterator::difference_type>(
                    this->stride);
}

template <typename T>
bool Slice<T>::iterator::operator==(const iterator &other) const noexcept {
  return this->pos == other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator!=(const iterator &other) const noexcept {
  return this->pos != other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator<(const iterator &other) const noexcept {
  return this->pos < other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator<=(const iterator &other) const noexcept {
  return this->pos <= other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator>(const iterator &other) const noexcept {
  return this->pos > other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator>=(const iterator &other) const noexcept {
  return this->pos >= other.pos;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::begin() const noexcept {
  iterator it;
  it.pos = slicePtr(this);
  it.stride = size_of<T>();
  return it;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::end() const noexcept {
  iterator it = this->begin();
  it.pos = static_cast<char *>(it.pos) + it.stride * this->size();
  return it;
}

template <typename T>
void Slice<T>::swap(Slice &rhs) noexcept {
  std::swap(*this, rhs);
}
#endif // CXXBRIDGE1_RUST_SLICE

#ifndef CXXBRIDGE1_RUST_BOX
#define CXXBRIDGE1_RUST_BOX
template <typename T>
class Box final {
public:
  using element_type = T;
  using const_pointer =
      typename std::add_pointer<typename std::add_const<T>::type>::type;
  using pointer = typename std::add_pointer<T>::type;

  Box() = delete;
  Box(Box &&) noexcept;
  ~Box() noexcept;

  explicit Box(const T &);
  explicit Box(T &&);

  Box &operator=(Box &&) & noexcept;

  const T *operator->() const noexcept;
  const T &operator*() const noexcept;
  T *operator->() noexcept;
  T &operator*() noexcept;

  template <typename... Fields>
  static Box in_place(Fields &&...);

  void swap(Box &) noexcept;

  static Box from_raw(T *) noexcept;

  T *into_raw() noexcept;

  /* Deprecated */ using value_type = element_type;

private:
  class uninit;
  class allocation;
  Box(uninit) noexcept;
  void drop() noexcept;

  friend void swap(Box &lhs, Box &rhs) noexcept { lhs.swap(rhs); }

  T *ptr;
};

template <typename T>
class Box<T>::uninit {};

template <typename T>
class Box<T>::allocation {
  static T *alloc() noexcept;
  static void dealloc(T *) noexcept;

public:
  allocation() noexcept : ptr(alloc()) {}
  ~allocation() noexcept {
    if (this->ptr) {
      dealloc(this->ptr);
    }
  }
  T *ptr;
};

template <typename T>
Box<T>::Box(Box &&other) noexcept : ptr(other.ptr) {
  other.ptr = nullptr;
}

template <typename T>
Box<T>::Box(const T &val) {
  allocation alloc;
  ::new (alloc.ptr) T(val);
  this->ptr = alloc.ptr;
  alloc.ptr = nullptr;
}

template <typename T>
Box<T>::Box(T &&val) {
  allocation alloc;
  ::new (alloc.ptr) T(std::move(val));
  this->ptr = alloc.ptr;
  alloc.ptr = nullptr;
}

template <typename T>
Box<T>::~Box() noexcept {
  if (this->ptr) {
    this->drop();
  }
}

template <typename T>
Box<T> &Box<T>::operator=(Box &&other) & noexcept {
  if (this->ptr) {
    this->drop();
  }
  this->ptr = other.ptr;
  other.ptr = nullptr;
  return *this;
}

template <typename T>
const T *Box<T>::operator->() const noexcept {
  return this->ptr;
}

template <typename T>
const T &Box<T>::operator*() const noexcept {
  return *this->ptr;
}

template <typename T>
T *Box<T>::operator->() noexcept {
  return this->ptr;
}

template <typename T>
T &Box<T>::operator*() noexcept {
  return *this->ptr;
}

template <typename T>
template <typename... Fields>
Box<T> Box<T>::in_place(Fields &&...fields) {
  allocation alloc;
  auto ptr = alloc.ptr;
  ::new (ptr) T{std::forward<Fields>(fields)...};
  alloc.ptr = nullptr;
  return from_raw(ptr);
}

template <typename T>
void Box<T>::swap(Box &rhs) noexcept {
  using std::swap;
  swap(this->ptr, rhs.ptr);
}

template <typename T>
Box<T> Box<T>::from_raw(T *raw) noexcept {
  Box box = uninit{};
  box.ptr = raw;
  return box;
}

template <typename T>
T *Box<T>::into_raw() noexcept {
  T *raw = this->ptr;
  this->ptr = nullptr;
  return raw;
}

template <typename T>
Box<T>::Box(uninit) noexcept {}
#endif // CXXBRIDGE1_RUST_BOX

#ifndef CXXBRIDGE1_RUST_BITCOPY_T
#define CXXBRIDGE1_RUST_BITCOPY_T
struct unsafe_bitcopy_t final {
  explicit unsafe_bitcopy_t() = default;
};
#endif // CXXBRIDGE1_RUST_BITCOPY_T

#ifndef CXXBRIDGE1_RUST_BITCOPY
#define CXXBRIDGE1_RUST_BITCOPY
constexpr unsafe_bitcopy_t unsafe_bitcopy{};
#endif // CXXBRIDGE1_RUST_BITCOPY

#ifndef CXXBRIDGE1_RUST_VEC
#define CXXBRIDGE1_RUST_VEC
template <typename T>
class Vec final {
public:
  using value_type = T;

  Vec() noexcept;
  Vec(std::initializer_list<T>);
  Vec(const Vec &);
  Vec(Vec &&) noexcept;
  ~Vec() noexcept;

  Vec &operator=(Vec &&) & noexcept;
  Vec &operator=(const Vec &) &;

  std::size_t size() const noexcept;
  bool empty() const noexcept;
  const T *data() const noexcept;
  T *data() noexcept;
  std::size_t capacity() const noexcept;

  const T &operator[](std::size_t n) const noexcept;
  const T &at(std::size_t n) const;
  const T &front() const noexcept;
  const T &back() const noexcept;

  T &operator[](std::size_t n) noexcept;
  T &at(std::size_t n);
  T &front() noexcept;
  T &back() noexcept;

  void reserve(std::size_t new_cap);
  void push_back(const T &value);
  void push_back(T &&value);
  template <typename... Args>
  void emplace_back(Args &&...args);
  void truncate(std::size_t len);
  void clear();

  using iterator = typename Slice<T>::iterator;
  iterator begin() noexcept;
  iterator end() noexcept;

  using const_iterator = typename Slice<const T>::iterator;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  void swap(Vec &) noexcept;

  Vec(unsafe_bitcopy_t, const Vec &) noexcept;

private:
  void reserve_total(std::size_t new_cap) noexcept;
  void set_len(std::size_t len) noexcept;
  void drop() noexcept;

  friend void swap(Vec &lhs, Vec &rhs) noexcept { lhs.swap(rhs); }

  std::array<std::uintptr_t, 3> repr;
};

template <typename T>
Vec<T>::Vec(std::initializer_list<T> init) : Vec{} {
  this->reserve_total(init.size());
  std::move(init.begin(), init.end(), std::back_inserter(*this));
}

template <typename T>
Vec<T>::Vec(const Vec &other) : Vec() {
  this->reserve_total(other.size());
  std::copy(other.begin(), other.end(), std::back_inserter(*this));
}

template <typename T>
Vec<T>::Vec(Vec &&other) noexcept : repr(other.repr) {
  new (&other) Vec();
}

template <typename T>
Vec<T>::~Vec() noexcept {
  this->drop();
}

template <typename T>
Vec<T> &Vec<T>::operator=(Vec &&other) & noexcept {
  this->drop();
  this->repr = other.repr;
  new (&other) Vec();
  return *this;
}

template <typename T>
Vec<T> &Vec<T>::operator=(const Vec &other) & {
  if (this != &other) {
    this->drop();
    new (this) Vec(other);
  }
  return *this;
}

template <typename T>
bool Vec<T>::empty() const noexcept {
  return this->size() == 0;
}

template <typename T>
T *Vec<T>::data() noexcept {
  return const_cast<T *>(const_cast<const Vec<T> *>(this)->data());
}

template <typename T>
const T &Vec<T>::operator[](std::size_t n) const noexcept {
  assert(n < this->size());
  auto data = reinterpret_cast<const char *>(this->data());
  return *reinterpret_cast<const T *>(data + n * size_of<T>());
}

template <typename T>
const T &Vec<T>::at(std::size_t n) const {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Vec index out of range");
  }
  return (*this)[n];
}

template <typename T>
const T &Vec<T>::front() const noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
const T &Vec<T>::back() const noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
T &Vec<T>::operator[](std::size_t n) noexcept {
  assert(n < this->size());
  auto data = reinterpret_cast<char *>(this->data());
  return *reinterpret_cast<T *>(data + n * size_of<T>());
}

template <typename T>
T &Vec<T>::at(std::size_t n) {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Vec index out of range");
  }
  return (*this)[n];
}

template <typename T>
T &Vec<T>::front() noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
T &Vec<T>::back() noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
void Vec<T>::reserve(std::size_t new_cap) {
  this->reserve_total(new_cap);
}

template <typename T>
void Vec<T>::push_back(const T &value) {
  this->emplace_back(value);
}

template <typename T>
void Vec<T>::push_back(T &&value) {
  this->emplace_back(std::move(value));
}

template <typename T>
template <typename... Args>
void Vec<T>::emplace_back(Args &&...args) {
  auto size = this->size();
  this->reserve_total(size + 1);
  ::new (reinterpret_cast<T *>(reinterpret_cast<char *>(this->data()) +
                               size * size_of<T>()))
      T(std::forward<Args>(args)...);
  this->set_len(size + 1);
}

template <typename T>
void Vec<T>::clear() {
  this->truncate(0);
}

template <typename T>
typename Vec<T>::iterator Vec<T>::begin() noexcept {
  return Slice<T>(this->data(), this->size()).begin();
}

template <typename T>
typename Vec<T>::iterator Vec<T>::end() noexcept {
  return Slice<T>(this->data(), this->size()).end();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::begin() const noexcept {
  return this->cbegin();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::end() const noexcept {
  return this->cend();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::cbegin() const noexcept {
  return Slice<const T>(this->data(), this->size()).begin();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::cend() const noexcept {
  return Slice<const T>(this->data(), this->size()).end();
}

template <typename T>
void Vec<T>::swap(Vec &rhs) noexcept {
  using std::swap;
  swap(this->repr, rhs.repr);
}

template <typename T>
Vec<T>::Vec(unsafe_bitcopy_t, const Vec &bits) noexcept : repr(bits.repr) {}
#endif // CXXBRIDGE1_RUST_VEC

#ifndef CXXBRIDGE1_RUST_OPAQUE
#define CXXBRIDGE1_RUST_OPAQUE
class Opaque {
public:
  Opaque() = delete;
  Opaque(const Opaque &) = delete;
  ~Opaque() = delete;
};
#endif // CXXBRIDGE1_RUST_OPAQUE

#ifndef CXXBRIDGE1_IS_COMPLETE
#define CXXBRIDGE1_IS_COMPLETE
namespace detail {
namespace {
template <typename T, typename = std::size_t>
struct is_complete : std::false_type {};
template <typename T>
struct is_complete<T, decltype(sizeof(T))> : std::true_type {};
} // namespace
} // namespace detail
#endif // CXXBRIDGE1_IS_COMPLETE

#ifndef CXXBRIDGE1_LAYOUT
#define CXXBRIDGE1_LAYOUT
class layout {
  template <typename T>
  friend std::size_t size_of();
  template <typename T>
  friend std::size_t align_of();
  template <typename T>
  static typename std::enable_if<std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_size_of() {
    return T::layout::size();
  }
  template <typename T>
  static typename std::enable_if<!std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_size_of() {
    return sizeof(T);
  }
  template <typename T>
  static
      typename std::enable_if<detail::is_complete<T>::value, std::size_t>::type
      size_of() {
    return do_size_of<T>();
  }
  template <typename T>
  static typename std::enable_if<std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_align_of() {
    return T::layout::align();
  }
  template <typename T>
  static typename std::enable_if<!std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_align_of() {
    return alignof(T);
  }
  template <typename T>
  static
      typename std::enable_if<detail::is_complete<T>::value, std::size_t>::type
      align_of() {
    return do_align_of<T>();
  }
};

template <typename T>
std::size_t size_of() {
  return layout::size_of<T>();
}

template <typename T>
std::size_t align_of() {
  return layout::align_of<T>();
}
#endif // CXXBRIDGE1_LAYOUT

namespace repr {
struct PtrLen final {
  void *ptr;
  ::std::size_t len;
};
} // namespace repr

namespace detail {
class Fail final {
  ::rust::repr::PtrLen &throw$;
public:
  Fail(::rust::repr::PtrLen &throw$) noexcept : throw$(throw$) {}
  void operator()(char const *) noexcept;
  void operator()(std::string const &) noexcept;
};
} // namespace detail

namespace {
template <bool> struct deleter_if {
  template <typename T> void operator()(T *) {}
};
template <> struct deleter_if<true> {
  template <typename T> void operator()(T *ptr) { ptr->~T(); }
};
} // namespace
} // namespace cxxbridge1

namespace behavior {
class missing {};
missing trycatch(...);

template <typename Try, typename Fail>
static typename ::std::enable_if<::std::is_same<
    decltype(trycatch(::std::declval<Try>(), ::std::declval<Fail>())),
    missing>::value>::type
trycatch(Try &&func, Fail &&fail) noexcept try {
  func();
} catch (::std::exception const &e) {
  fail(e.what());
}
} // namespace behavior
} // namespace rust

#if __cplusplus >= 201402L
#define CXX_DEFAULT_VALUE(value) = value
#else
#define CXX_DEFAULT_VALUE(value)
#endif

struct DelegatedCredential;
struct ServiceCredential;
struct VerificationInfo;
struct CertificateData;
struct CertificatePublic;
struct ReadOutcome;
struct IoContext;
struct ReadWaker;
using FizzPrivateKey = ::FizzPrivateKey;
using FizzCredentialGenerator = ::FizzCredentialGenerator;
using FizzServerContext = ::FizzServerContext;
using FizzServerConnection = ::FizzServerConnection;
using FizzClientContext = ::FizzClientContext;
using FizzClientConnection = ::FizzClientConnection;

#ifndef CXXBRIDGE1_STRUCT_DelegatedCredential
#define CXXBRIDGE1_STRUCT_DelegatedCredential
// Raw delegated credential data structure
struct DelegatedCredential final {
  // Validity time in seconds from certificate's notBefore
  ::std::uint32_t valid_time CXX_DEFAULT_VALUE(0);
  // Signature scheme for handshake signature verification
  ::std::uint16_t expected_verify_scheme CXX_DEFAULT_VALUE(0);
  // DER-encoded public key (hex string)
  ::rust::String public_key_der;
  // Signature scheme used to sign the credential
  ::std::uint16_t credential_scheme CXX_DEFAULT_VALUE(0);
  // Signature over the credential (hex string)
  ::rust::String signature;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_DelegatedCredential

#ifndef CXXBRIDGE1_STRUCT_ServiceCredential
#define CXXBRIDGE1_STRUCT_ServiceCredential
// Complete delegated credential with metadata
struct ServiceCredential final {
  // Service name this credential is for
  ::rust::String service_name;
  // The delegated credential itself
  ::DelegatedCredential credential;
  // Private key for the credential (PEM format)
  ::rust::String private_key_pem;
  // Public key in DER format (hex string)
  ::rust::String public_key_der;
  // When the credential was created (Unix timestamp)
  ::std::uint64_t created_at CXX_DEFAULT_VALUE(0);
  // When the credential expires (Unix timestamp)
  ::std::uint64_t expires_at CXX_DEFAULT_VALUE(0);
  // Combined PEM format (credential + private key)
  ::rust::String credential_pem;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_ServiceCredential

#ifndef CXXBRIDGE1_STRUCT_VerificationInfo
#define CXXBRIDGE1_STRUCT_VerificationInfo
// Public verification information for clients
struct VerificationInfo final {
  // Service name
  ::rust::String service_name;
  // Validity time in seconds
  ::std::uint32_t valid_time CXX_DEFAULT_VALUE(0);
  // Expected signature scheme for verification
  ::std::uint16_t expected_verify_scheme CXX_DEFAULT_VALUE(0);
  // Public key in DER format (hex string)
  ::rust::String public_key_der;
  // Expiration timestamp (Unix timestamp)
  ::std::uint64_t expires_at CXX_DEFAULT_VALUE(0);

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_VerificationInfo

#ifndef CXXBRIDGE1_STRUCT_CertificateData
#define CXXBRIDGE1_STRUCT_CertificateData
// Certificate and private key data
struct CertificateData final {
  // Certificate in PEM format
  ::rust::String cert_pem;
  // Private key in PEM format
  ::rust::String key_pem;
  // Supported signature schemes
  ::rust::Vec<::std::uint16_t> sig_schemes;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_CertificateData

#ifndef CXXBRIDGE1_STRUCT_CertificatePublic
#define CXXBRIDGE1_STRUCT_CertificatePublic
// Certificate without private key (public component only)
struct CertificatePublic final {
  // Certificate in PEM format
  ::rust::String cert_pem;
  // Supported signature schemes
  ::rust::Vec<::std::uint16_t> sig_schemes;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_CertificatePublic

#ifndef CXXBRIDGE1_STRUCT_ReadOutcome
#define CXXBRIDGE1_STRUCT_ReadOutcome
// Outcome of a coalesced poll-read FFI call. Avoids 2-3 cxx round-trips
// (size_hint + read_eof + read) per `poll_read`.
struct ReadOutcome final {
  // Number of bytes actually copied into the caller's buffer.
  ::std::uint64_t bytes_read CXX_DEFAULT_VALUE(0);
  // True iff the peer has closed and no more data will arrive.
  bool eof CXX_DEFAULT_VALUE(false);

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_ReadOutcome

#ifndef CXXBRIDGE1_STRUCT_IoContext
#define CXXBRIDGE1_STRUCT_IoContext
struct IoContext final : public ::rust::Opaque {
  ~IoContext() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_IoContext

#ifndef CXXBRIDGE1_STRUCT_ReadWaker
#define CXXBRIDGE1_STRUCT_ReadWaker
// Opaque Rust `Waker` slot. `poll_read` registers a `Waker` into it;
// C++ read callbacks call `wake_read_waker` to fire it.
struct ReadWaker final : public ::rust::Opaque {
  ~ReadWaker() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_ReadWaker

extern "C" {
::std::size_t cxxbridge1$IoContext$operator$sizeof() noexcept;
::std::size_t cxxbridge1$IoContext$operator$alignof() noexcept;

void cxxbridge1$handle_io_result(::IoContext *context, ::std::size_t bytes, ::rust::String *error) noexcept;
::std::size_t cxxbridge1$ReadWaker$operator$sizeof() noexcept;
::std::size_t cxxbridge1$ReadWaker$operator$alignof() noexcept;

void cxxbridge1$wake_read_waker(::ReadWaker const &waker) noexcept;

::rust::repr::PtrLen cxxbridge1$load_certificate_from_pem(::rust::Str cert_pem, ::rust::Str key_pem, ::CertificateData *return$) noexcept {
  ::CertificateData (*load_certificate_from_pem$)(::rust::Str, ::rust::Str) = ::load_certificate_from_pem;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::CertificateData(load_certificate_from_pem$(cert_pem, key_pem));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$load_certificate_from_file(::rust::Str cert_path, ::rust::Str key_path, ::CertificateData *return$) noexcept {
  ::CertificateData (*load_certificate_from_file$)(::rust::Str, ::rust::Str) = ::load_certificate_from_file;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::CertificateData(load_certificate_from_file$(cert_path, key_path));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$load_certificate_public_from_pem(::rust::Str cert_pem, ::CertificatePublic *return$) noexcept {
  ::CertificatePublic (*load_certificate_public_from_pem$)(::rust::Str) = ::load_certificate_public_from_pem;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::CertificatePublic(load_certificate_public_from_pem$(cert_pem));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$load_certificate_public_from_file(::rust::Str cert_path, ::CertificatePublic *return$) noexcept {
  ::CertificatePublic (*load_certificate_public_from_file$)(::rust::Str) = ::load_certificate_public_from_file;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::CertificatePublic(load_certificate_public_from_file$(cert_path));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$get_certificate_sig_schemes(::CertificateData const &cert_data, ::rust::Vec<::std::uint16_t> *return$) noexcept {
  ::rust::Vec<::std::uint16_t> (*get_certificate_sig_schemes$)(::CertificateData const &) = ::get_certificate_sig_schemes;
  new (return$) ::rust::Vec<::std::uint16_t>(get_certificate_sig_schemes$(cert_data));
}

void cxxbridge1$certificate_to_pem(::CertificateData const &cert_data, ::rust::String *return$) noexcept {
  ::rust::String (*certificate_to_pem$)(::CertificateData const &) = ::certificate_to_pem;
  new (return$) ::rust::String(certificate_to_pem$(cert_data));
}

::rust::repr::PtrLen cxxbridge1$load_private_key_from_pem(::rust::Str key_pem, ::FizzPrivateKey **return$) noexcept {
  ::std::unique_ptr<::FizzPrivateKey> (*load_private_key_from_pem$)(::rust::Str) = ::load_private_key_from_pem;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzPrivateKey *(load_private_key_from_pem$(key_pem).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$generate_ec_p256_keypair(::FizzPrivateKey **return$) noexcept {
  ::std::unique_ptr<::FizzPrivateKey> (*generate_ec_p256_keypair$)() = ::generate_ec_p256_keypair;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzPrivateKey *(generate_ec_p256_keypair$().release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$private_key_to_pem(::FizzPrivateKey const &key, ::rust::String *return$) noexcept {
  ::rust::String (*private_key_to_pem$)(::FizzPrivateKey const &) = ::private_key_to_pem;
  new (return$) ::rust::String(private_key_to_pem$(key));
}

void cxxbridge1$get_public_key_der(::FizzPrivateKey const &key, ::rust::String *return$) noexcept {
  ::rust::String (*get_public_key_der$)(::FizzPrivateKey const &) = ::get_public_key_der;
  new (return$) ::rust::String(get_public_key_der$(key));
}

::rust::repr::PtrLen cxxbridge1$new_credential_generator(::CertificateData const &parent_cert, ::FizzCredentialGenerator **return$) noexcept {
  ::std::unique_ptr<::FizzCredentialGenerator> (*new_credential_generator$)(::CertificateData const &) = ::new_credential_generator;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzCredentialGenerator *(new_credential_generator$(parent_cert).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$generate_delegated_credential(::FizzCredentialGenerator const &generator, ::rust::Str service_name, ::std::uint32_t valid_seconds, ::ServiceCredential *return$) noexcept {
  ::ServiceCredential (*generate_delegated_credential$)(::FizzCredentialGenerator const &, ::rust::Str, ::std::uint32_t) = ::generate_delegated_credential;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::ServiceCredential(generate_delegated_credential$(generator, service_name, valid_seconds));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$verify_delegated_credential(::FizzCredentialGenerator const &generator, ::ServiceCredential const &credential, bool *return$) noexcept {
  bool (*verify_delegated_credential$)(::FizzCredentialGenerator const &, ::ServiceCredential const &) = ::verify_delegated_credential;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) bool(verify_delegated_credential$(generator, credential));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$delegated_credential_to_pem(::ServiceCredential const &credential, ::rust::String *return$) noexcept {
  ::rust::String (*delegated_credential_to_pem$)(::ServiceCredential const &) = ::delegated_credential_to_pem;
  new (return$) ::rust::String(delegated_credential_to_pem$(credential));
}

::rust::repr::PtrLen cxxbridge1$load_delegated_credential_from_pem(::rust::Str pem, ::ServiceCredential *return$) noexcept {
  ::ServiceCredential (*load_delegated_credential_from_pem$)(::rust::Str) = ::load_delegated_credential_from_pem;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::ServiceCredential(load_delegated_credential_from_pem$(pem));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$get_public_verification_info(::ServiceCredential const &credential, ::VerificationInfo *return$) noexcept {
  ::VerificationInfo (*get_public_verification_info$)(::ServiceCredential const &) = ::get_public_verification_info;
  new (return$) ::VerificationInfo(get_public_verification_info$(credential));
}

void cxxbridge1$verification_info_to_json(::VerificationInfo const &info, ::rust::String *return$) noexcept {
  ::rust::String (*verification_info_to_json$)(::VerificationInfo const &) = ::verification_info_to_json;
  new (return$) ::rust::String(verification_info_to_json$(info));
}

::rust::repr::PtrLen cxxbridge1$verification_info_from_json(::rust::Str json, ::VerificationInfo *return$) noexcept {
  ::VerificationInfo (*verification_info_from_json$)(::rust::Str) = ::verification_info_from_json;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::VerificationInfo(verification_info_from_json$(json));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$new_server_tls_context(::CertificatePublic const &parent_cert, ::ServiceCredential const &delegated_cred, ::FizzServerContext **return$) noexcept {
  ::std::unique_ptr<::FizzServerContext> (*new_server_tls_context$)(::CertificatePublic const &, ::ServiceCredential const &) = ::new_server_tls_context;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzServerContext *(new_server_tls_context$(parent_cert, delegated_cred).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$new_server_tls_context_no_dc(::CertificateData const &parent_cert, ::FizzServerContext **return$) noexcept {
  ::std::unique_ptr<::FizzServerContext> (*new_server_tls_context_no_dc$)(::CertificateData const &) = ::new_server_tls_context_no_dc;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzServerContext *(new_server_tls_context_no_dc$(parent_cert).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$server_context_set_alpn_protocols(::FizzServerContext &ctx, ::rust::Vec<::rust::String> const *protocols) noexcept {
  void (*server_context_set_alpn_protocols$)(::FizzServerContext &, ::rust::Vec<::rust::String>) = ::server_context_set_alpn_protocols;
  server_context_set_alpn_protocols$(ctx, ::rust::Vec<::rust::String>(::rust::unsafe_bitcopy, *protocols));
}

::rust::repr::PtrLen cxxbridge1$server_accept_connection(::FizzServerContext const &ctx, ::std::int32_t fd, ::FizzServerConnection **return$) noexcept {
  ::std::unique_ptr<::FizzServerConnection> (*server_accept_connection$)(::FizzServerContext const &, ::std::int32_t) = ::server_accept_connection;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzServerConnection *(server_accept_connection$(ctx, fd).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$server_connection_handshake(::FizzServerConnection &conn) noexcept {
  void (*server_connection_handshake$)(::FizzServerConnection &) = ::server_connection_handshake;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        server_connection_handshake$(conn);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

bool cxxbridge1$server_connection_is_open(::FizzServerConnection const &conn) noexcept {
  bool (*server_connection_is_open$)(::FizzServerConnection const &) = ::server_connection_is_open;
  return server_connection_is_open$(conn);
}

void cxxbridge1$server_connection_close(::FizzServerConnection &conn) noexcept {
  void (*server_connection_close$)(::FizzServerConnection &) = ::server_connection_close;
  server_connection_close$(conn);
}

::rust::repr::PtrLen cxxbridge1$server_connection_read(::FizzServerConnection &conn, ::rust::Slice<::std::uint8_t > buf, ::std::size_t *return$) noexcept {
  ::std::size_t (*server_connection_read$)(::FizzServerConnection &, ::rust::Slice<::std::uint8_t >) = ::server_connection_read;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::size_t(server_connection_read$(conn, buf));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$server_read_size_hint(::FizzServerConnection &conn, ::std::size_t *return$) noexcept {
  ::std::size_t (*server_read_size_hint$)(::FizzServerConnection &) = ::server_read_size_hint;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::size_t(server_read_size_hint$(conn));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

bool cxxbridge1$server_connection_read_eof(::FizzServerConnection const &conn) noexcept {
  bool (*server_connection_read_eof$)(::FizzServerConnection const &) = ::server_connection_read_eof;
  return server_connection_read_eof$(conn);
}

::rust::repr::PtrLen cxxbridge1$server_connection_read_or_status(::FizzServerConnection &conn, ::rust::Slice<::std::uint8_t > buf, ::ReadOutcome *return$) noexcept {
  ::ReadOutcome (*server_connection_read_or_status$)(::FizzServerConnection &, ::rust::Slice<::std::uint8_t >) = ::server_connection_read_or_status;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::ReadOutcome(server_connection_read_or_status$(conn, buf));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$server_connection_write(::FizzServerConnection &conn, ::rust::Slice<::std::uint8_t const> buf, ::std::size_t *return$) noexcept {
  ::std::size_t (*server_connection_write$)(::FizzServerConnection &, ::rust::Slice<::std::uint8_t const>) = ::server_connection_write;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::size_t(server_connection_write$(conn, buf));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$new_client_tls_context(::VerificationInfo const &verification_info, ::rust::Str ca_cert_path, ::FizzClientContext **return$) noexcept {
  ::std::unique_ptr<::FizzClientContext> (*new_client_tls_context$)(::VerificationInfo const &, ::rust::Str) = ::new_client_tls_context;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzClientContext *(new_client_tls_context$(verification_info, ca_cert_path).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$new_client_tls_context_no_dc(::rust::Str ca_cert_path, ::FizzClientContext **return$) noexcept {
  ::std::unique_ptr<::FizzClientContext> (*new_client_tls_context_no_dc$)(::rust::Str) = ::new_client_tls_context_no_dc;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzClientContext *(new_client_tls_context_no_dc$(ca_cert_path).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$client_context_set_alpn_protocols(::FizzClientContext &ctx, ::rust::Vec<::rust::String> const *protocols) noexcept {
  void (*client_context_set_alpn_protocols$)(::FizzClientContext &, ::rust::Vec<::rust::String>) = ::client_context_set_alpn_protocols;
  client_context_set_alpn_protocols$(ctx, ::rust::Vec<::rust::String>(::rust::unsafe_bitcopy, *protocols));
}

void cxxbridge1$client_context_set_sni(::FizzClientContext &ctx, ::rust::Str hostname) noexcept {
  void (*client_context_set_sni$)(::FizzClientContext &, ::rust::Str) = ::client_context_set_sni;
  client_context_set_sni$(ctx, hostname);
}

::rust::repr::PtrLen cxxbridge1$client_connect(::FizzClientContext const &ctx, ::std::int32_t fd, ::rust::Str hostname, ::FizzClientConnection **return$) noexcept {
  ::std::unique_ptr<::FizzClientConnection> (*client_connect$)(::FizzClientContext const &, ::std::int32_t, ::rust::Str) = ::client_connect;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::FizzClientConnection *(client_connect$(ctx, fd, hostname).release());
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$client_connection_handshake(::FizzClientConnection &conn) noexcept {
  void (*client_connection_handshake$)(::FizzClientConnection &) = ::client_connection_handshake;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        client_connection_handshake$(conn);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

bool cxxbridge1$client_connection_is_open(::FizzClientConnection const &conn) noexcept {
  bool (*client_connection_is_open$)(::FizzClientConnection const &) = ::client_connection_is_open;
  return client_connection_is_open$(conn);
}

void cxxbridge1$client_connection_close(::FizzClientConnection &conn) noexcept {
  void (*client_connection_close$)(::FizzClientConnection &) = ::client_connection_close;
  client_connection_close$(conn);
}

::rust::repr::PtrLen cxxbridge1$client_connection_read(::FizzClientConnection &conn, ::rust::Slice<::std::uint8_t > buf, ::std::size_t *return$) noexcept {
  ::std::size_t (*client_connection_read$)(::FizzClientConnection &, ::rust::Slice<::std::uint8_t >) = ::client_connection_read;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::size_t(client_connection_read$(conn, buf));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$client_read_size_hint(::FizzClientConnection &conn, ::std::size_t *return$) noexcept {
  ::std::size_t (*client_read_size_hint$)(::FizzClientConnection &) = ::client_read_size_hint;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::size_t(client_read_size_hint$(conn));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

bool cxxbridge1$client_connection_read_eof(::FizzClientConnection const &conn) noexcept {
  bool (*client_connection_read_eof$)(::FizzClientConnection const &) = ::client_connection_read_eof;
  return client_connection_read_eof$(conn);
}

::rust::repr::PtrLen cxxbridge1$client_connection_read_or_status(::FizzClientConnection &conn, ::rust::Slice<::std::uint8_t > buf, ::ReadOutcome *return$) noexcept {
  ::ReadOutcome (*client_connection_read_or_status$)(::FizzClientConnection &, ::rust::Slice<::std::uint8_t >) = ::client_connection_read_or_status;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::ReadOutcome(client_connection_read_or_status$(conn, buf));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$client_connection_write(::FizzClientConnection &conn, ::rust::Slice<::std::uint8_t const> buf, ::std::size_t *return$) noexcept {
  ::std::size_t (*client_connection_write$)(::FizzClientConnection &, ::rust::Slice<::std::uint8_t const>) = ::client_connection_write;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::size_t(client_connection_write$(conn, buf));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$client_connection_peer_cert(::FizzClientConnection const &conn, ::rust::String *return$) noexcept {
  ::rust::String (*client_connection_peer_cert$)(::FizzClientConnection const &) = ::client_connection_peer_cert;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::rust::String(client_connection_peer_cert$(conn));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$server_connection_handshake_async(::FizzServerConnection &conn, ::IoContext *context) noexcept {
  void (*server_connection_handshake_async$)(::FizzServerConnection &, ::rust::Box<::IoContext>) = ::server_connection_handshake_async;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        server_connection_handshake_async$(conn, ::rust::Box<::IoContext>::from_raw(context));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$client_connection_handshake_async(::FizzClientConnection &conn, ::IoContext *context) noexcept {
  void (*client_connection_handshake_async$)(::FizzClientConnection &, ::rust::Box<::IoContext>) = ::client_connection_handshake_async;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        client_connection_handshake_async$(conn, ::rust::Box<::IoContext>::from_raw(context));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

void cxxbridge1$set_server_read_waker(::FizzServerConnection &conn, ::ReadWaker *waker) noexcept {
  void (*set_server_read_waker$)(::FizzServerConnection &, ::rust::Box<::ReadWaker>) = ::set_server_read_waker;
  set_server_read_waker$(conn, ::rust::Box<::ReadWaker>::from_raw(waker));
}

void cxxbridge1$set_client_read_waker(::FizzClientConnection &conn, ::ReadWaker *waker) noexcept {
  void (*set_client_read_waker$)(::FizzClientConnection &, ::rust::Box<::ReadWaker>) = ::set_client_read_waker;
  set_client_read_waker$(conn, ::rust::Box<::ReadWaker>::from_raw(waker));
}

::rust::repr::PtrLen cxxbridge1$run_fizz_cpp_bench(::FizzServerContext const &server_ctx, ::FizzClientContext const &client_ctx, ::std::uint64_t pairs, ::std::uint64_t batch_size, ::std::uint64_t rounds, ::std::uint64_t *return$) noexcept {
  ::std::uint64_t (*run_fizz_cpp_bench$)(::FizzServerContext const &, ::FizzClientContext const &, ::std::uint64_t, ::std::uint64_t, ::std::uint64_t) = ::run_fizz_cpp_bench;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        new (return$) ::std::uint64_t(run_fizz_cpp_bench$(server_ctx, client_ctx, pairs, batch_size, rounds));
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}
} // extern "C"

::std::size_t IoContext::layout::size() noexcept {
  return cxxbridge1$IoContext$operator$sizeof();
}

::std::size_t IoContext::layout::align() noexcept {
  return cxxbridge1$IoContext$operator$alignof();
}

void handle_io_result(::rust::Box<::IoContext> context, ::std::size_t bytes, ::rust::String error) noexcept {
  cxxbridge1$handle_io_result(context.into_raw(), bytes, &error);
}

::std::size_t ReadWaker::layout::size() noexcept {
  return cxxbridge1$ReadWaker$operator$sizeof();
}

::std::size_t ReadWaker::layout::align() noexcept {
  return cxxbridge1$ReadWaker$operator$alignof();
}

void wake_read_waker(::ReadWaker const &waker) noexcept {
  cxxbridge1$wake_read_waker(waker);
}

extern "C" {
::IoContext *cxxbridge1$box$IoContext$alloc() noexcept;
void cxxbridge1$box$IoContext$dealloc(::IoContext *) noexcept;
void cxxbridge1$box$IoContext$drop(::rust::Box<::IoContext> *ptr) noexcept;

static_assert(::rust::detail::is_complete<::std::remove_extent<::FizzPrivateKey>::type>::value, "definition of `::FizzPrivateKey` is required");
static_assert(sizeof(::std::unique_ptr<::FizzPrivateKey>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::FizzPrivateKey>) == alignof(void *), "");
void cxxbridge1$unique_ptr$FizzPrivateKey$null(::std::unique_ptr<::FizzPrivateKey> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzPrivateKey>();
}
void cxxbridge1$unique_ptr$FizzPrivateKey$raw(::std::unique_ptr<::FizzPrivateKey> *ptr, ::std::unique_ptr<::FizzPrivateKey>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzPrivateKey>(raw);
}
::std::unique_ptr<::FizzPrivateKey>::element_type const *cxxbridge1$unique_ptr$FizzPrivateKey$get(::std::unique_ptr<::FizzPrivateKey> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::FizzPrivateKey>::pointer cxxbridge1$unique_ptr$FizzPrivateKey$release(::std::unique_ptr<::FizzPrivateKey> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$FizzPrivateKey$drop(::std::unique_ptr<::FizzPrivateKey> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::FizzPrivateKey>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::FizzCredentialGenerator>::type>::value, "definition of `::FizzCredentialGenerator` is required");
static_assert(sizeof(::std::unique_ptr<::FizzCredentialGenerator>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::FizzCredentialGenerator>) == alignof(void *), "");
void cxxbridge1$unique_ptr$FizzCredentialGenerator$null(::std::unique_ptr<::FizzCredentialGenerator> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzCredentialGenerator>();
}
void cxxbridge1$unique_ptr$FizzCredentialGenerator$raw(::std::unique_ptr<::FizzCredentialGenerator> *ptr, ::std::unique_ptr<::FizzCredentialGenerator>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzCredentialGenerator>(raw);
}
::std::unique_ptr<::FizzCredentialGenerator>::element_type const *cxxbridge1$unique_ptr$FizzCredentialGenerator$get(::std::unique_ptr<::FizzCredentialGenerator> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::FizzCredentialGenerator>::pointer cxxbridge1$unique_ptr$FizzCredentialGenerator$release(::std::unique_ptr<::FizzCredentialGenerator> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$FizzCredentialGenerator$drop(::std::unique_ptr<::FizzCredentialGenerator> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::FizzCredentialGenerator>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::FizzServerContext>::type>::value, "definition of `::FizzServerContext` is required");
static_assert(sizeof(::std::unique_ptr<::FizzServerContext>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::FizzServerContext>) == alignof(void *), "");
void cxxbridge1$unique_ptr$FizzServerContext$null(::std::unique_ptr<::FizzServerContext> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzServerContext>();
}
void cxxbridge1$unique_ptr$FizzServerContext$raw(::std::unique_ptr<::FizzServerContext> *ptr, ::std::unique_ptr<::FizzServerContext>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzServerContext>(raw);
}
::std::unique_ptr<::FizzServerContext>::element_type const *cxxbridge1$unique_ptr$FizzServerContext$get(::std::unique_ptr<::FizzServerContext> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::FizzServerContext>::pointer cxxbridge1$unique_ptr$FizzServerContext$release(::std::unique_ptr<::FizzServerContext> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$FizzServerContext$drop(::std::unique_ptr<::FizzServerContext> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::FizzServerContext>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::FizzServerConnection>::type>::value, "definition of `::FizzServerConnection` is required");
static_assert(sizeof(::std::unique_ptr<::FizzServerConnection>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::FizzServerConnection>) == alignof(void *), "");
void cxxbridge1$unique_ptr$FizzServerConnection$null(::std::unique_ptr<::FizzServerConnection> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzServerConnection>();
}
void cxxbridge1$unique_ptr$FizzServerConnection$raw(::std::unique_ptr<::FizzServerConnection> *ptr, ::std::unique_ptr<::FizzServerConnection>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzServerConnection>(raw);
}
::std::unique_ptr<::FizzServerConnection>::element_type const *cxxbridge1$unique_ptr$FizzServerConnection$get(::std::unique_ptr<::FizzServerConnection> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::FizzServerConnection>::pointer cxxbridge1$unique_ptr$FizzServerConnection$release(::std::unique_ptr<::FizzServerConnection> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$FizzServerConnection$drop(::std::unique_ptr<::FizzServerConnection> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::FizzServerConnection>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::FizzClientContext>::type>::value, "definition of `::FizzClientContext` is required");
static_assert(sizeof(::std::unique_ptr<::FizzClientContext>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::FizzClientContext>) == alignof(void *), "");
void cxxbridge1$unique_ptr$FizzClientContext$null(::std::unique_ptr<::FizzClientContext> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzClientContext>();
}
void cxxbridge1$unique_ptr$FizzClientContext$raw(::std::unique_ptr<::FizzClientContext> *ptr, ::std::unique_ptr<::FizzClientContext>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzClientContext>(raw);
}
::std::unique_ptr<::FizzClientContext>::element_type const *cxxbridge1$unique_ptr$FizzClientContext$get(::std::unique_ptr<::FizzClientContext> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::FizzClientContext>::pointer cxxbridge1$unique_ptr$FizzClientContext$release(::std::unique_ptr<::FizzClientContext> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$FizzClientContext$drop(::std::unique_ptr<::FizzClientContext> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::FizzClientContext>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::FizzClientConnection>::type>::value, "definition of `::FizzClientConnection` is required");
static_assert(sizeof(::std::unique_ptr<::FizzClientConnection>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::FizzClientConnection>) == alignof(void *), "");
void cxxbridge1$unique_ptr$FizzClientConnection$null(::std::unique_ptr<::FizzClientConnection> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzClientConnection>();
}
void cxxbridge1$unique_ptr$FizzClientConnection$raw(::std::unique_ptr<::FizzClientConnection> *ptr, ::std::unique_ptr<::FizzClientConnection>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::FizzClientConnection>(raw);
}
::std::unique_ptr<::FizzClientConnection>::element_type const *cxxbridge1$unique_ptr$FizzClientConnection$get(::std::unique_ptr<::FizzClientConnection> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::FizzClientConnection>::pointer cxxbridge1$unique_ptr$FizzClientConnection$release(::std::unique_ptr<::FizzClientConnection> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$FizzClientConnection$drop(::std::unique_ptr<::FizzClientConnection> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::FizzClientConnection>::value>{}(ptr);
}

::ReadWaker *cxxbridge1$box$ReadWaker$alloc() noexcept;
void cxxbridge1$box$ReadWaker$dealloc(::ReadWaker *) noexcept;
void cxxbridge1$box$ReadWaker$drop(::rust::Box<::ReadWaker> *ptr) noexcept;
} // extern "C"

namespace rust {
inline namespace cxxbridge1 {
template <>
::IoContext *Box<::IoContext>::allocation::alloc() noexcept {
  return cxxbridge1$box$IoContext$alloc();
}
template <>
void Box<::IoContext>::allocation::dealloc(::IoContext *ptr) noexcept {
  cxxbridge1$box$IoContext$dealloc(ptr);
}
template <>
void Box<::IoContext>::drop() noexcept {
  cxxbridge1$box$IoContext$drop(this);
}
template <>
::ReadWaker *Box<::ReadWaker>::allocation::alloc() noexcept {
  return cxxbridge1$box$ReadWaker$alloc();
}
template <>
void Box<::ReadWaker>::allocation::dealloc(::ReadWaker *ptr) noexcept {
  cxxbridge1$box$ReadWaker$dealloc(ptr);
}
template <>
void Box<::ReadWaker>::drop() noexcept {
  cxxbridge1$box$ReadWaker$drop(this);
}
} // namespace cxxbridge1
} // namespace rust
