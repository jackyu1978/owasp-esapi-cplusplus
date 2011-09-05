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
    : m_base("") { }

  SecureString::SecureString(const char* s, size_t n)
    : m_base(s, n) { }

  SecureString::SecureString(const char* s)
    : m_base(s) { }

  SecureString::SecureString(size_t n, char c)
    : m_base(n, c) { }

  SecureString::SecureString(const std::string& str)
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

  SecureString& SecureString::operator=(const std::string& str)
  {
    m_base.assign(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::operator=(const char* str)
  {
    m_base.assign(str);
    return *this;
  }

  SecureString& SecureString::operator=(char c)
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

  SecureString& SecureString::operator+=(const std::string& str)
  {
    m_base.append(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::operator+=(const char* str)
  {
    m_base.append(str);
    return *this;
  }

  SecureString& SecureString::operator+=(char c)
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

  SecureString& SecureString::append(const std::string& str)
  {
    m_base.append(str.data(), str.size());
    return *this;
  }

  SecureString& SecureString::append(const char* str)
  {
    m_base.append(str);

    return *this;
  }

  SecureString& SecureString::append(const char* str, size_t n)
  {
    m_base.append(str, n);

    return *this;
  }

  SecureString& SecureString::append(size_t n, char c)
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

  SecureString& SecureString::assign(const std::string& str)
  {
    m_base.assign(str.data(), str.size());

    return *this;
  }

  SecureString& SecureString::assign(const char* str)
  {
    m_base.assign(str);

    return *this;
  }

  SecureString& SecureString::assign(const char* str, size_t n)
  {
    m_base.assign(str, n);

    return *this;
  }

  SecureString& SecureString::assign(size_t n, char c)
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

  SecureString& SecureString::insert(size_t pos, const std::string& str)
  {
    m_base.insert(pos, str.data(), str.size());

    return *this;
  }

  SecureString& SecureString::insert(size_t pos1, const SecureString& str, size_t pos2, size_t n)
  {
    m_base.insert(pos1, str.m_base, pos2, n);

    return *this;
  }

  SecureString& SecureString::insert(size_t pos1, const std::string& str, size_t pos2, size_t n)
  {
    m_base.insert(pos1, SecureStringBase(str.data(), str.size()), pos2, n);

    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const char* s, size_t n)
  {
    m_base.insert(pos, s, n);

    return *this;
  }

  SecureString& SecureString::insert(size_t pos, const char* s)
  {
    m_base.insert(pos, s);

    return *this;
  }

  bool SecureString::empty() const
  {
    return m_base.empty();
  }

  const char* SecureString::c_str() const
  {
    return m_base.c_str();
  }

  const char* SecureString::data() const
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

  const char& SecureString::operator[] ( size_t pos ) const
  {
    return m_base.operator [](pos);
  }

  char& SecureString::operator[] ( size_t pos )
  {
    return m_base.operator [](pos);
  }

  const char& SecureString::at(size_t pos) const
  {
    return m_base.at(pos);
  }

  char& SecureString::at(size_t pos)
  {
    return m_base.at(pos);
  }

  // Swap
  void SecureString::swap(SecureString& str)
  {
    m_base.swap(str.m_base);
  }

  void SecureString::swap(std::string& str)
  {
    SecureStringBase temp(str.data(), str.size());
    m_base.swap(temp);
    str = std::string(temp.data(), temp.size());
  }

  // Forward find
  size_t SecureString::find(const SecureString& str, size_t pos) const
  {
    return m_base.find(str.m_base, pos);
  }

  size_t SecureString::find(const std::string& str, size_t pos) const
  {
    return m_base.find(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find(const char* s, size_t pos, size_t n) const
  {
    return m_base.find(s, pos, n);
  }

  size_t SecureString::find(const char* s, size_t pos) const
  {
    return m_base.find(s, pos);
  }

  size_t SecureString::find(char c, size_t pos) const
  {
    return m_base.find(c, pos);
  }

  // Reverse find
  size_t SecureString::rfind(const SecureString& str, size_t pos) const
  {
    return m_base.rfind(str.m_base, pos);
  }

  size_t SecureString::rfind(const std::string& str, size_t pos) const
  {
    return m_base.rfind(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::rfind(const char* s, size_t pos, size_t n) const
  {
    return m_base.rfind(s, pos, n);
  }

  size_t SecureString::rfind(const char* s, size_t pos) const
  {
    return m_base.rfind(s, pos);
  }

  size_t SecureString::rfind(char c, size_t pos) const
  {
    return m_base.rfind(c, pos);
  }

  // find_first_of
  size_t SecureString::find_first_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_first_of(str.m_base, pos);
  }

  size_t SecureString::find_first_of(const std::string& str, size_t pos) const
  {
    return m_base.find_first_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_first_of(const char* s, size_t pos, size_t n) const
  {
    return m_base.find_first_of(s, pos, n);
  }

  size_t SecureString::find_first_of(const char* s, size_t pos) const
  {
    return m_base.find_first_of(s, pos);
  }

  size_t SecureString::find_first_of(char c, size_t pos) const
  {
    return m_base.find_first_of(c, pos);
  }

  // find_last_of
  size_t SecureString::find_last_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_last_of(str.m_base, pos);
  }

  size_t SecureString::find_last_of(const std::string& str, size_t pos) const
  {
    return m_base.find_last_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_last_of(const char* s, size_t pos, size_t n) const
  {
    return m_base.find_last_of(s, pos, n);
  }

  size_t SecureString::find_last_of(const char* s, size_t pos) const
  {
    return m_base.find_last_of(s, pos);
  }

  size_t SecureString::find_last_of(char c, size_t pos) const
  {
    return m_base.find_last_of(c, pos);
  }

  // find_first_not_of
  size_t SecureString::find_first_not_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_first_not_of(str.m_base, pos);
  }

  size_t SecureString::find_first_not_of(const std::string& str, size_t pos) const
  {
    return m_base.find_first_not_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_first_not_of(const char* s, size_t pos, size_t n) const
  {
    return m_base.find_first_not_of(s, pos, n);
  }

  size_t SecureString::find_first_not_of(const char* s, size_t pos) const
  {
    return m_base.find_first_not_of(s, pos);
  }

  size_t SecureString::find_first_not_of(char c, size_t pos) const
  {
    return m_base.find_first_not_of(c, pos);
  }

  // find_last_not_of
  size_t SecureString::find_last_not_of(const SecureString& str, size_t pos) const
  {
    return m_base.find_last_not_of(str.m_base, pos);
  }

  size_t SecureString::find_last_not_of(const std::string& str, size_t pos) const
  {
    return m_base.find_last_not_of(SecureStringBase(str.data(), str.size()), pos);
  }

  size_t SecureString::find_last_not_of(const char* s, size_t pos, size_t n) const
  {
    return m_base.find_last_not_of(s, pos, n);
  }

  size_t SecureString::find_last_not_of(const char* s, size_t pos) const
  {
    return m_base.find_last_not_of(s, pos);
  }

  size_t SecureString::find_last_not_of(char c, size_t pos) const
  {
    return m_base.find_last_not_of(c, pos);
  }

  // compare
  int SecureString::compare(const SecureString& str) const
  {
    return m_base.compare(str.m_base);
  }

  int SecureString::compare(const std::string& str) const
  {
    return m_base.compare(SecureStringBase(str.data(), str.size()));
  }

  int SecureString::compare(size_t pos, size_t n, const SecureString& str) const
  {
    return m_base.compare(pos, n, str.m_base);
  }

  int SecureString::compare(size_t pos, size_t n, const std::string& str) const
  {
    return m_base.compare(pos, n, SecureStringBase(str.data(), str.size()));
  }

  int SecureString::compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const
  {
    return m_base.compare(pos1, n1, str.m_base, pos2, n2);
  }

  int SecureString::compare(size_t pos1, size_t n1, const std::string& str, size_t pos2, size_t n2) const
  {
    return m_base.compare(pos1, n1, SecureStringBase(str.data(), str.size()), pos2, n2);
  }

  int SecureString::compare(const char* s) const
  {
    return m_base.compare(s);
  }

  int SecureString::compare(size_t pos, size_t n, const char* s) const
  {
    return m_base.compare(pos, n, s);
  }

  int SecureString::compare(size_t pos1, size_t n1, const char* s, size_t n2) const
  {
    return m_base.compare(pos1, n1, s, n2);
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
