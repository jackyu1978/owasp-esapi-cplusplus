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
    : ThisBase("") { }

  SecureString::SecureString(const char* s, size_t n)
    : ThisBase(s, n) { }

  SecureString::SecureString(const char* s)
    : ThisBase(s) { }

  SecureString::SecureString(size_t n, char c)
    : ThisBase(n, c) { }

  SecureString::SecureString(const std::string& str)
    : ThisBase(str.data(), str.size()) { }

  template<class InputIterator>
  SecureString::SecureString(InputIterator begin, InputIterator end)
    : ThisBase(begin, end) { }

  SecureString::SecureString(const SecureString& str)
    : ThisBase(str) { }

  // Assignment
  SecureString& SecureString::operator=(const SecureString& str)
  {
    return assign(str);
  }

  SecureString& SecureString::operator=(const std::string& str)
  {
    return assign(str.data(), (size_t)str.size());
  }

  SecureString& SecureString::operator=(const char* str)
  {
    return assign(str);
  }

  SecureString& SecureString::operator=(char c)
  {
    return assign(1, c);
  }

  // Append
  SecureString& SecureString::operator+=(const SecureString& str)
  {
    return append(str);
  }

  SecureString& SecureString::operator+=(const std::string& str)
  {
    return append(str.data(), str.size());
  }

  SecureString& SecureString::operator+=(const char* str)
  {
    return append(str);
  }

  SecureString& SecureString::operator+=(char c)
  {
    return append(1, c);
  }

  // Append
  SecureString& SecureString::append(const SecureString& str)
  {
    ThisBase::append(str);

    return *this;
  }

  SecureString& SecureString::append(const std::string& str)
  {
    ThisBase::append(str.data(), str.size());

    return *this;
  }

  SecureString& SecureString::append(const char* str)
  {
    ThisBase::append(str);

    return *this;
  }

  SecureString& SecureString::append(const char* str, size_t n)
  {
    ThisBase::append(str, n);

    return *this;
  }

  SecureString& SecureString::append(size_t n, char c)
  {
    ThisBase::append(n, c);

    return *this;
  }

  // Assign
  SecureString& SecureString::assign(const SecureString& str)
  {
    ThisBase::assign(str);

    return *this;
  }

  SecureString& SecureString::assign(const std::string& str)
  {
    ThisBase::assign(str.data(), str.size());

    return *this;
  }

  SecureString& SecureString::assign(const char* str)
  {
    ThisBase::assign(str);

    return *this;
  }

  SecureString& SecureString::assign(const char* str, size_t n)
  {
    ThisBase::assign(str, n);

    return *this;
  }

  SecureString& SecureString::assign(size_t n, char c)
  {
    ThisBase::assign(n, c);

    return *this;
  }

  // Insert
  SecureString& SecureString::insert(size_t pos, const SecureString& str)
  {
    ThisBase::insert(pos, str);

    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const std::string& str)
  {
    ThisBase::insert(pos, str.data(), str.size());

    return *this;
  }

  SecureString& SecureString::insert(size_t pos1, const SecureString& str, size_t pos2, size_t n)
  {
    ThisBase::insert(pos1, str, pos2, n);

    return *this;
  }

  SecureString& SecureString::insert(size_t pos1, const std::string& str, size_t pos2, size_t n)
  {
    ThisBase::insert(pos1, SecureString(str.data(), str.size()), pos2, n);

    return *this;
  }

  // Swap
  void SecureString::swap(SecureString& str)
  {
    ThisBase::swap(str);
  }

  void SecureString::swap(std::string& str)
  {
    SecureString temp(str.data(), str.size());

    ThisBase::swap(temp);

    str = std::string(temp.data(), temp.size());
  }

  // Forward find
  size_t SecureString::find(const SecureString& str, size_t pos) const
  {
    return ThisBase::find(str, pos);
  }

  size_t SecureString::find(const std::string& str, size_t pos) const
  {
    return ThisBase::find(SecureString(str.data(), str.size()), pos);
  }

  size_t SecureString::find(const char* s, size_t pos, size_t n) const
  {
    return ThisBase::find(s, pos, n);
  }

  size_t SecureString::find(const char* s, size_t pos) const
  {
    return ThisBase::find(s, pos);
  }

  size_t SecureString::find(char c, size_t pos) const
  {
    return ThisBase::find(c, pos);
  }

  // Reverse find
  size_t SecureString::rfind(const SecureString& str, size_t pos) const
  {
    return ThisBase::rfind(str, pos);
  }

  size_t SecureString::rfind(const std::string& str, size_t pos) const
  {
    return ThisBase::rfind(SecureString(str.data(), str.size()), pos);
  }

  size_t SecureString::rfind(const char* s, size_t pos, size_t n) const
  {
    return ThisBase::rfind(s, pos, n);
  }

  size_t SecureString::rfind(const char* s, size_t pos) const
  {
    return ThisBase::rfind(s, pos);
  }

  size_t SecureString::rfind(char c, size_t pos) const
  {
    return ThisBase::rfind(c, pos);
  }

  // find_first_of
  size_t SecureString::find_first_of(const SecureString& str, size_t pos) const
  {
    return ThisBase::find_first_of(str, pos);
  }

  size_t SecureString::find_first_of(const std::string& str, size_t pos) const
  {
    return ThisBase::find_first_of(SecureString(str.data(), str.size()), pos);
  }

  size_t SecureString::find_first_of(const char* s, size_t pos, size_t n) const
  {
    return ThisBase::find_first_of(s, pos, n);
  }

  size_t SecureString::find_first_of(const char* s, size_t pos) const
  {
    return ThisBase::find_first_of(s, pos);
  }

  size_t SecureString::find_first_of(char c, size_t pos) const
  {
    return ThisBase::find_first_of(c, pos);
  }

  // find_last_of
  size_t SecureString::find_last_of(const SecureString& str, size_t pos) const
  {
    return ThisBase::find_last_of(str, pos);
  }

  size_t SecureString::find_last_of(const std::string& str, size_t pos) const
  {
    return ThisBase::find_last_of(SecureString(str.data(), str.size()), pos);
  }

  size_t SecureString::find_last_of(const char* s, size_t pos, size_t n) const
  {
    return ThisBase::find_last_of(s, pos, n);
  }

  size_t SecureString::find_last_of(const char* s, size_t pos) const
  {
    return ThisBase::find_last_of(s, pos);
  }

  size_t SecureString::find_last_of(char c, size_t pos) const
  {
    return ThisBase::find_last_of(c, pos);
  }

  // find_first_not_of
  size_t SecureString::find_first_not_of(const SecureString& str, size_t pos) const
  {
    return ThisBase::find_first_not_of(str, pos);
  }

  size_t SecureString::find_first_not_of(const std::string& str, size_t pos) const
  {
    return ThisBase::find_first_not_of(SecureString(str.data(), str.size()), pos);
  }

  size_t SecureString::find_first_not_of(const char* s, size_t pos, size_t n) const
  {
    return ThisBase::find_first_not_of(s, pos, n);
  }

  size_t SecureString::find_first_not_of(const char* s, size_t pos) const
  {
    return ThisBase::find_first_not_of(s, pos);
  }

  size_t SecureString::find_first_not_of(char c, size_t pos) const
  {
    return ThisBase::find_first_not_of(c, pos);
  }

  // find_last_not_of
  size_t SecureString::find_last_not_of(const SecureString& str, size_t pos) const
  {
    return ThisBase::find_last_not_of(str, pos);
  }

  size_t SecureString::find_last_not_of(const std::string& str, size_t pos) const
  {
    return ThisBase::find_last_not_of(SecureString(str.data(), str.size()), pos);
  }

  size_t SecureString::find_last_not_of(const char* s, size_t pos, size_t n) const
  {
    return ThisBase::find_last_not_of(s, pos, n);
  }

  size_t SecureString::find_last_not_of(const char* s, size_t pos) const
  {
    return ThisBase::find_last_not_of(s, pos);
  }

  size_t SecureString::find_last_not_of(char c, size_t pos) const
  {
    return ThisBase::find_last_not_of(c, pos);
  }

  // compare
  int SecureString::compare(const SecureString& str) const
  {
    return ThisBase::compare(str);
  }

  int SecureString::compare(const std::string& str) const
  {
    return ThisBase::compare(SecureString(str.data(), str.size()));
  }

  int SecureString::compare(size_t pos, size_t n, const SecureString& str) const
  {
    return ThisBase::compare(pos, n, str);
  }

  int SecureString::compare(size_t pos, size_t n, const std::string& str) const
  {
    return ThisBase::compare(pos, n, SecureString(str.data(), str.size()));
  }

  int SecureString::compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const
  {
    return ThisBase::compare(pos1, n1, str, pos2, n2);
  }

  int SecureString::compare(size_t pos1, size_t n1, const std::string& str, size_t pos2, size_t n2) const
  {
    return ThisBase::compare(pos1, n1, SecureString(str.data(), str.size()), pos2, n2);
  }

  int SecureString::compare(const char* s) const
  {
    return ThisBase::compare(s);
  }

  int SecureString::compare(size_t pos, size_t n, const char* s) const
  {
    return ThisBase::compare(pos, n, s);
  }

  int SecureString::compare(size_t pos1, size_t n1, const char* s, size_t n2) const
  {
    return ThisBase::compare(pos1, n1, s, pos2, n2);
  }
}

bool operator==(const std::string& s, const esapi::SecureString& ss)
{
  // Avoid creating the temporary. Are we shooting ourselves
  // in the foot by not allowing CharTraits to work its magic?
  // return (s.size() == ss.size()) && (0 == ::memcmp(s.data(), ss.data(), s.size()));
  return ss.compare(s) == 0;
}

bool operator==(const esapi::SecureString& ss, const std::string& s)
{
  return operator==(s, ss);
}
