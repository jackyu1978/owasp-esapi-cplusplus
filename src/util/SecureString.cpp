/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#include "util/SecureString.h"

namespace esapi
{
  // Construction
  SecureString::SecureString()
    : m_base() { }

  SecureString::SecureString(const Char* s, size_t n)
    : m_base(s, n) { ASSERT(s); ASSERT(n); }

  SecureString::SecureString(const byte* s, size_t n)
    : m_base((const Char*)s, n) { ASSERT(s); ASSERT(n); }

  SecureString::SecureString(const Char* s)
    : m_base(s) { ASSERT(s); }

  SecureString::SecureString(size_t n, Char c)
    : m_base(n, c) { ASSERT(n); }

  SecureString::SecureString(const String& str)
    : m_base(str.data(), str.size()) { }

  template<class InputIterator>
  SecureString::SecureString(InputIterator begin, InputIterator end)
    : m_base(begin, end) { }

  SecureString::SecureString(const SecureString& str)
    : m_base(str.m_base) { }

  // Iterators
  SecureString::iterator SecureString::begin()
  {
    return m_base.begin();
  }

  SecureString::const_iterator SecureString::begin() const
  {
    return m_base.begin();
  }

  SecureString::iterator SecureString::end()
  {
    return m_base.end();
  }

  SecureString::const_iterator SecureString::end() const
  {
    return m_base.end();
  }

  SecureString::reverse_iterator SecureString::rbegin()
  {
    return m_base.rbegin();
  }

  SecureString::const_reverse_iterator SecureString::rbegin() const
  {
    return m_base.rbegin();
  }

  SecureString::reverse_iterator SecureString::rend()
  {
    return m_base.rend();
  }

  SecureString::const_reverse_iterator SecureString::rend() const
  {
    return m_base.rend();
  }
  
  SecureString::size_type SecureString::max_size() const
  {
    return m_base.max_size();
  }

  size_t SecureString::capacity() const
  {
    return m_base.capacity();
  }

  void SecureString::reserve(size_t cnt)
  {
    m_base.reserve(cnt);
  }

  void SecureString::clear()
  {
    m_base.clear();
  }

  // Assignment
  SecureString& SecureString::operator=(const SecureString& str)
  {
    if(this != &str)
      {
        m_base.assign(str.m_base);
      }

    return *this;
  }

  SecureString& SecureString::operator=(const String& str)
  {
    m_base.assign(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::operator=(const Char* str)
  {
    ASSERT(str);
    m_base.assign(str);
    return *this;
  }

  SecureString& SecureString::operator=(Char c)
  {
    m_base.assign(1, c);
    return *this;
  }

  // Append
  SecureString& SecureString::operator+=(const SecureString& str)
  {
    m_base.append(str.m_base);
    return *this;
  }

  SecureString& SecureString::operator+=(const String& str)
  {
    m_base.append(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::operator+=(const Char* str)
  {
    ASSERT(str);
    m_base.append(str);
    return *this;
  }

  SecureString& SecureString::operator+=(Char c)
  {
    m_base.append(1, c);
    return *this;
  }

  // Append
  SecureString& SecureString::append(const SecureString& str)
  {
    m_base.append(str.m_base);
    return *this;
  }

  SecureString& SecureString::append(const String& str)
  {
    m_base.append(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::append(const Char* str)
  {
    ASSERT(str);
    m_base.append(str);
    return *this;
  }

  SecureString& SecureString::append(const Char* str, size_t n)
  {
    ASSERT(str); ASSERT(n);
    m_base.append(str, n);
    return *this;
  }

  SecureString& SecureString::append(const byte* bin, size_t n)
  {
    ASSERT(bin); ASSERT(n);
    m_base.append((const Char*)bin, n);
    return *this;
  }

  SecureString& SecureString::append(size_t n, Char c)
  {
    m_base.append(n, c);
    return *this;
  }

  // Assign
  SecureString& SecureString::assign(const SecureString& str)
  {
    m_base.assign(str.m_base);
    return *this;
  }

  SecureString& SecureString::assign(const String& str)
  {
    m_base.assign(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::assign(const Char* str)
  {
    ASSERT(str);
    m_base.assign(str);
    return *this;
  }

  SecureString& SecureString::assign(const Char* str, size_t n)
  {
    ASSERT(str); ASSERT(n);
    m_base.assign(str, n);
    return *this;
  }

  SecureString& SecureString::assign(const byte* bin, size_t n)
  {
    ASSERT(bin); ASSERT(n);
    m_base.assign((const Char*)bin, n);
    return *this;
  }

  SecureString& SecureString::assign(size_t n, Char c)
  {
    m_base.assign(n, c);
    return *this;
  }

  // Insert
  SecureString& SecureString::insert(size_t pos, const SecureString& str)
  {
    m_base.insert(pos, str.m_base);
    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const String& str)
  {
    m_base.insert(pos, str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::insert(size_t pos1, const SecureString& str, size_t pos2, size_t n)
  {
    m_base.insert(pos1, str.m_base, pos2, n);
    return *this;
  }

  SecureString& SecureString::insert(size_t pos1, const String& str, size_t pos2, size_t n)
  {
    m_base.insert(pos1, SecureStringBase(str.data(), str.size()), pos2, n);
    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const Char* s, size_t n)
  {
    ASSERT(s); ASSERT(n);
    m_base.insert(pos, s, n);
    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const byte* b, size_t n)
  {
    ASSERT(b); ASSERT(n);
    m_base.insert(pos, (const Char*)b, n);
    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const Char* s)
  {
    ASSERT(s);
    m_base.insert(pos, s);
    return *this;
  }


  bool SecureString::empty() const
  {
    return m_base.empty();
  }

  const Char* SecureString::c_str() const
  {
    return m_base.c_str();
  }

  const Char* SecureString::data() const
  {
    return m_base.data();
  }

  SecureString::size_type SecureString::length() const
  {
    return m_base.length();
  }

  SecureString::size_type SecureString::size() const
  {
    return m_base.size();
  }

  SecureString& SecureString::erase(size_t pos, size_t n)
  {
    m_base.erase(pos, n);
    return *this;
  }

  SecureString::iterator SecureString::erase(iterator position)
  {
    return m_base.erase(position);
  }

  SecureString::iterator SecureString::erase(iterator first, iterator last)
  {
    return m_base.erase(first, last);
  }

  const Char& SecureString::operator[] ( size_t pos ) const
  {
    return m_base.operator [](pos);
  }

  Char& SecureString::operator[] ( size_t pos )
  {
    return m_base.operator [](pos);
  }

  const Char& SecureString::at(size_t pos) const
  {
    return m_base.at(pos);
  }

  Char& SecureString::at(size_t pos)
  {
    return m_base.at(pos);
  }

  // Swap
  void SecureString::swap(SecureString& str)
  {
    m_base.swap(str.m_base);
  }

  // Forward find
  size_t SecureString::find(const SecureString& str, size_t pos) const
  {
    return m_base.find(str.m_base, pos);
  }

  size_t SecureString::find(const String& str, size_t pos) const
  {
    return m_base.find(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find(const Char* s, size_t pos, size_t n) const
  {
    ASSERT(s); ASSERT(n);
    return m_base.find(s, pos, n);
  }

  size_t SecureString::find(const Char* s, size_t pos) const
  {
    ASSERT(s);
    return m_base.find(s, pos);
  }

  size_t SecureString::find(Char c, size_t pos) const
  {
    return m_base.find(c, pos);
  }

  // Reverse find
  size_t SecureString::rfind(const SecureString& str, size_t pos) const
  {
    return m_base.rfind(str.m_base, pos);
  }

  size_t SecureString::rfind(const String& str, size_t pos) const
  {
    return m_base.rfind(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::rfind(const Char* s, size_t pos, size_t n) const
  {
    ASSERT(s); ASSERT(n);
    return m_base.rfind(s, pos, n);
  }

  size_t SecureString::rfind(const Char* s, size_t pos) const
  {
    ASSERT(s);
    return m_base.rfind(s, pos);
  }

  size_t SecureString::rfind(Char c, size_t pos) const
  {
    return m_base.rfind(c, pos);
  }

  // find_first_of
  size_t SecureString::find_first_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_first_of(str.m_base, pos);
  }

  size_t SecureString::find_first_of(const String& str, size_t pos) const
  {
    return m_base.find_first_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_first_of(const Char* s, size_t pos, size_t n) const
  {
    ASSERT(s); ASSERT(n);
    return m_base.find_first_of(s, pos, n);
  }

  size_t SecureString::find_first_of(const Char* s, size_t pos) const
  {
    ASSERT(s);
    return m_base.find_first_of(s, pos);
  }

  size_t SecureString::find_first_of(Char c, size_t pos) const
  {
    return m_base.find_first_of(c, pos);
  }

  // find_last_of
  size_t SecureString::find_last_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_last_of(str.m_base, pos);
  }

  size_t SecureString::find_last_of(const String& str, size_t pos) const
  {
    return m_base.find_last_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_last_of(const Char* s, size_t pos, size_t n) const
  {
    return m_base.find_last_of(s, pos, n);
  }

  size_t SecureString::find_last_of(const Char* s, size_t pos) const
  {
    ASSERT(s);
    return m_base.find_last_of(s, pos);
  }

  size_t SecureString::find_last_of(Char c, size_t pos) const
  {
    return m_base.find_last_of(c, pos);
  }

  // find_first_not_of
  size_t SecureString::find_first_not_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_first_not_of(str.m_base, pos);
  }

  size_t SecureString::find_first_not_of(const String& str, size_t pos) const
  {
    return m_base.find_first_not_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_first_not_of(const Char* s, size_t pos, size_t n) const
  {
    ASSERT(s); ASSERT(n);
    return m_base.find_first_not_of(s, pos, n);
  }

  size_t SecureString::find_first_not_of(const Char* s, size_t pos) const
  {
    ASSERT(s);
    return m_base.find_first_not_of(s, pos);
  }

  size_t SecureString::find_first_not_of(Char c, size_t pos) const
  {
    return m_base.find_first_not_of(c, pos);
  }

  // find_last_not_of
  size_t SecureString::find_last_not_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_last_not_of(str.m_base, pos);
  }

  size_t SecureString::find_last_not_of(const String& str, size_t pos) const
  {
    return m_base.find_last_not_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_last_not_of(const Char* s, size_t pos, size_t n) const
  {
    return m_base.find_last_not_of(s, pos, n);
  }

  size_t SecureString::find_last_not_of(const Char* s, size_t pos) const
  {
    ASSERT(s);
    return m_base.find_last_not_of(s, pos);
  }

  size_t SecureString::find_last_not_of(Char c, size_t pos) const
  {
    return m_base.find_last_not_of(c, pos);
  }

  // compare
  int SecureString::compare(const SecureString& str) const
  {
    return m_base.compare(str.m_base);
  }

  int SecureString::compare(const String& str) const
  {
    return m_base.compare(0, str.size(), str.data());
  }

  int SecureString::compare(size_t pos, size_t n, const SecureString& str) const
  {
    return m_base.compare(pos, n, str.m_base);
  }

  int SecureString::compare(size_t pos, size_t n, const String& str) const
  {
    return m_base.compare(pos, n, SecureStringBase(str.data(), str.size()));
  }

  int SecureString::compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const
  {
    return m_base.compare(pos1, n1, str.m_base, pos2, n2);
  }

  int SecureString::compare(size_t pos1, size_t n1, const String& str, size_t pos2, size_t n2) const
  {
    return m_base.compare(pos1, n1, SecureStringBase(str.data(), str.size()), pos2, n2);
  }

  int SecureString::compare(const Char* s) const
  {
    ASSERT(s);
    return m_base.compare(s);
  }

  int SecureString::compare(size_t pos, size_t n, const Char* s) const
  {
    ASSERT(s);
    return m_base.compare(pos, n, s);
  }

  int SecureString::compare(size_t pos1, size_t n1, const Char* s, size_t n2) const
  {
    ASSERT(s);
    return m_base.compare(pos1, n1, s, n2);
  }

  bool operator==(const String& s, const esapi::SecureString& ss)
  {
    return ss.compare(0, s.size(), s.data()) == 0;
  }

  bool operator==(const esapi::SecureString& ss, const String& s)
  {  
    return ss.compare(0, s.size(), s.data()) == 0;
  }

} // esapi

// Effective C++, Item 25, pp 106-112
namespace std
{
  template <>
  void swap(esapi::SecureString& a, esapi::SecureString& b)
  {
    a.swap(b);
  }
}
