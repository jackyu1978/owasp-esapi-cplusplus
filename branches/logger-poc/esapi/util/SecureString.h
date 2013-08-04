/*
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* @author Kevin Wall, kevin.w.wall@gmail.com
* @author Jeffrey Walton, noloader@gmail.com
*/

#pragma once

#include "EsapiCommon.h"
#include "util/zAllocator.h"

#include <string>
using std::char_traits;
using std::basic_string;

//#if defined(_GLIBCXX_DEBUG)
//typedef __gnu_debug::basic_string< Char, std::char_traits<Char>, esapi::zallocator<Char> > SecureStringBase;
//#else
//typedef std::basic_string< Char, std::char_traits<Char>, esapi::zallocator<Char> > SecureStringBase;
//#endif

namespace esapi
{
  class ESAPI_EXPORT SecureString
  {
  public:

    typedef std::basic_string< Char, std::char_traits<Char>, esapi::zallocator<Char> > SecureStringBase;
    typedef zallocator<Char>::size_type size_type;
    static const size_type npos = static_cast<size_type>(-1);

    typedef SecureStringBase::value_type value_type;
    typedef SecureStringBase::pointer pointer;
    typedef SecureStringBase::const_pointer const_pointer;
    typedef SecureStringBase::iterator iterator;
    typedef SecureStringBase::const_iterator const_iterator;
    typedef SecureStringBase::reverse_iterator reverse_iterator;
    typedef SecureStringBase::const_reverse_iterator const_reverse_iterator;

    // Construction
    SecureString()
      : m_base() { }

    SecureString(const Char* s, size_t n)
      : m_base(s, n) { ASSERT(s); ASSERT(n); }

    SecureString(const byte* s, size_t n)
      : m_base((const Char*)s, n) { ASSERT(s); ASSERT(n); }

    SecureString(const Char* s)
      : m_base(s) { ASSERT(s); }

    SecureString(size_t n, Char c)
      : m_base(n, c) { ASSERT(n); }

    SecureString(const NarrowString& str)
      : m_base(str.data(), str.size()) { }

    template<class InputIterator>
    SecureString(InputIterator begin, InputIterator end)
      : m_base(begin, end) { }

    SecureString(const SecureString& str)
      : m_base(str.m_base) { }

    // Iterators
    iterator begin()
    {
      return m_base.begin();
    }

    const_iterator begin() const
    {
      return m_base.begin();
    }

    iterator end()
    {
      return m_base.end();
    }

    const_iterator end() const
    {
      return m_base.end();
    }

    reverse_iterator rbegin()
    {
      return m_base.rbegin();
    }

    const_reverse_iterator rbegin() const
    {
      return m_base.rbegin();
    }

    reverse_iterator rend()
    {
      return m_base.rend();
    }

    const_reverse_iterator rend() const
    {
      return m_base.rend();
    }

    size_type max_size() const
    {
      return m_base.max_size();
    }

    size_t capacity() const
    {
      return m_base.capacity();
    }

    void reserve(size_t cnt)
    {
      m_base.reserve(cnt);
    }

    void clear()
    {
      m_base.clear();
    }

    // Assignment
    SecureString& operator=(const SecureString& str)
    {
      if(this != &str)
      {
        m_base.assign(str.m_base);
      }

      return *this;
    }

    SecureString& operator=(const NarrowString& str)
    {
      m_base.assign(str.data(), str.size());
      return *this;
    }

    SecureString& operator=(const Char* str)
    {
      ASSERT(str);
      m_base.assign(str);
      return *this;
    }

    SecureString& operator=(Char c)
    {
      m_base.assign(1, c);
      return *this;
    }

    // Append
    SecureString& operator+=(const SecureString& str)
    {
      m_base.append(str.m_base);
      return *this;
    }

    SecureString& operator+=(const NarrowString& str)
    {
      m_base.append(str.data(), str.size());
      return *this;
    }

    SecureString& operator+=(const Char* str)
    {
      ASSERT(str);
      m_base.append(str);
      return *this;
    }

    SecureString& operator+=(Char c)
    {
      m_base.append(1, c);
      return *this;
    }

    // Append
    SecureString& append(const SecureString& str)
    {
      m_base.append(str.m_base);
      return *this;
    }

    SecureString& append(const NarrowString& str)
    {
      m_base.append(str.data(), str.size());
      return *this;
    }

    SecureString& append(const Char* str)
    {
      ASSERT(str);
      m_base.append(str);
      return *this;
    }

    SecureString& append(const Char* str, size_t n)
    {
      ASSERT(str); ASSERT(n);
      m_base.append(str, n);
      return *this;
    }

    SecureString& append(const byte* bin, size_t n)
    {
      ASSERT(bin); ASSERT(n);
      m_base.append((const Char*)bin, n);
      return *this;
    }

    SecureString& append(size_t n, Char c)
    {
      m_base.append(n, c);
      return *this;
    }

    // Assign
    SecureString& assign(const SecureString& str)
    {
      m_base.assign(str.m_base);
      return *this;
    }

    SecureString& assign(const NarrowString& str)
    {
      m_base.assign(str.data(), str.size());
      return *this;
    }

    SecureString& assign(const Char* str)
    {
      ASSERT(str);
      m_base.assign(str);
      return *this;
    }

    SecureString& assign(const Char* str, size_t n)
    {
      ASSERT(str); ASSERT(n);
      m_base.assign(str, n);
      return *this;
    }

    SecureString& assign(const byte* bin, size_t n)
    {
      ASSERT(bin); ASSERT(n);
      m_base.assign((const Char*)bin, n);
      return *this;
    }

    SecureString& assign(size_t n, Char c)
    {
      m_base.assign(n, c);
      return *this;
    }

    // Insert
    SecureString& insert(size_t pos, const SecureString& str)
    {
      m_base.insert(pos, str.m_base);
      return *this;
    }

    SecureString& insert(size_t pos, const NarrowString& str)
    {
      m_base.insert(pos, str.data(), str.size());
      return *this;
    }

    SecureString& insert(size_t pos1, const SecureString& str, size_t pos2, size_t n)
    {
      m_base.insert(pos1, str.m_base, pos2, n);
      return *this;
    }

    SecureString& insert(size_t pos1, const NarrowString& str, size_t pos2, size_t n)
    {
      m_base.insert(pos1, SecureStringBase(str.data(), str.size()), pos2, n);
      return *this;
    }

    SecureString& insert(size_t pos, const Char* s, size_t n)
    {
      ASSERT(s); ASSERT(n);
      m_base.insert(pos, s, n);
      return *this;
    }

    SecureString& insert(size_t pos, const byte* b, size_t n)
    {
      ASSERT(b); ASSERT(n);
      m_base.insert(pos, (const Char*)b, n);
      return *this;
    }

    SecureString& insert(size_t pos, const Char* s)
    {
      ASSERT(s);
      m_base.insert(pos, s);
      return *this;
    }


    bool empty() const
    {
      return m_base.empty();
    }

    const Char* c_str() const
    {
      return m_base.c_str();
    }

    const Char* data() const
    {
      return m_base.data();
    }

    size_type length() const
    {
      return m_base.length();
    }

    size_type size() const
    {
      return m_base.size();
    }

    SecureString& erase(size_t pos, size_t n)
    {
      m_base.erase(pos, n);
      return *this;
    }

    iterator erase(iterator position)
    {
      return m_base.erase(position);
    }

    iterator erase(iterator first, iterator last)
    {
      return m_base.erase(first, last);
    }

    const Char& operator[] ( size_t pos ) const
    {
      return m_base.operator [](pos);
    }

    Char& operator[] ( size_t pos )
    {
      return m_base.operator [](pos);
    }

    const Char& at(size_t pos) const
    {
      return m_base.at(pos);
    }

    Char& at(size_t pos)
    {
      return m_base.at(pos);
    }

    // Swap
    void swap(SecureString& str)
    {
      m_base.swap(str.m_base);
    }

    // Forward find
    size_t find(const SecureString& str, size_t pos) const
    {
      return m_base.find(str.m_base, pos);
    }

    size_t find(const NarrowString& str, size_t pos) const
    {
      return m_base.find(SecureStringBase(str.data(), str.size()), pos);
    }

    size_t find(const Char* s, size_t pos, size_t n) const
    {
      ASSERT(s); ASSERT(n);
      return m_base.find(s, pos, n);
    }

    size_t find(const Char* s, size_t pos) const
    {
      ASSERT(s);
      return m_base.find(s, pos);
    }

    size_t find(Char c, size_t pos) const
    {
      return m_base.find(c, pos);
    }

    // Reverse find
    size_t rfind(const SecureString& str, size_t pos) const
    {
      return m_base.rfind(str.m_base, pos);
    }

    size_t rfind(const NarrowString& str, size_t pos) const
    {
      return m_base.rfind(SecureStringBase(str.data(), str.size()), pos);
    }

    size_t rfind(const Char* s, size_t pos, size_t n) const
    {
      ASSERT(s); ASSERT(n);
      return m_base.rfind(s, pos, n);
    }

    size_t rfind(const Char* s, size_t pos) const
    {
      ASSERT(s);
      return m_base.rfind(s, pos);
    }

    size_t rfind(Char c, size_t pos) const
    {
      return m_base.rfind(c, pos);
    }

    // find_first_of
    size_t find_first_of(const SecureString& str, size_t pos) const
    {
      return m_base.find_first_of(str.m_base, pos);
    }

    size_t find_first_of(const NarrowString& str, size_t pos) const
    {
      return m_base.find_first_of(SecureStringBase(str.data(), str.size()), pos);
    }

    size_t find_first_of(const Char* s, size_t pos, size_t n) const
    {
      ASSERT(s); ASSERT(n);
      return m_base.find_first_of(s, pos, n);
    }

    size_t find_first_of(const Char* s, size_t pos) const
    {
      ASSERT(s);
      return m_base.find_first_of(s, pos);
    }

    size_t find_first_of(Char c, size_t pos) const
    {
      return m_base.find_first_of(c, pos);
    }

    // find_last_of
    size_t find_last_of(const SecureString& str, size_t pos) const
    {
      return m_base.find_last_of(str.m_base, pos);
    }

    size_t find_last_of(const NarrowString& str, size_t pos) const
    {
      return m_base.find_last_of(SecureStringBase(str.data(), str.size()), pos);
    }

    size_t find_last_of(const Char* s, size_t pos, size_t n) const
    {
      return m_base.find_last_of(s, pos, n);
    }

    size_t find_last_of(const Char* s, size_t pos) const
    {
      ASSERT(s);
      return m_base.find_last_of(s, pos);
    }

    size_t find_last_of(Char c, size_t pos) const
    {
      return m_base.find_last_of(c, pos);
    }

    // find_first_not_of
    size_t find_first_not_of(const SecureString& str, size_t pos) const
    {
      return m_base.find_first_not_of(str.m_base, pos);
    }

    size_t find_first_not_of(const NarrowString& str, size_t pos) const
    {
      return m_base.find_first_not_of(SecureStringBase(str.data(), str.size()), pos);
    }

    size_t find_first_not_of(const Char* s, size_t pos, size_t n) const
    {
      ASSERT(s); ASSERT(n);
      return m_base.find_first_not_of(s, pos, n);
    }

    size_t find_first_not_of(const Char* s, size_t pos) const
    {
      ASSERT(s);
      return m_base.find_first_not_of(s, pos);
    }

    size_t find_first_not_of(Char c, size_t pos) const
    {
      return m_base.find_first_not_of(c, pos);
    }

    // find_last_not_of
    size_t find_last_not_of(const SecureString& str, size_t pos) const
    {
      return m_base.find_last_not_of(str.m_base, pos);
    }

    size_t find_last_not_of(const NarrowString& str, size_t pos) const
    {
      return m_base.find_last_not_of(SecureStringBase(str.data(), str.size()), pos);
    }

    size_t find_last_not_of(const Char* s, size_t pos, size_t n) const
    {
      return m_base.find_last_not_of(s, pos, n);
    }

    size_t find_last_not_of(const Char* s, size_t pos) const
    {
      ASSERT(s);
      return m_base.find_last_not_of(s, pos);
    }

    size_t find_last_not_of(Char c, size_t pos) const
    {
      return m_base.find_last_not_of(c, pos);
    }

    // compare
    int compare(const SecureString& str) const
    {
      return m_base.compare(str.m_base);
    }

    int compare(const NarrowString& str) const
    {
      return m_base.compare(0, str.size(), str.data());
    }

    int compare(size_t pos, size_t n, const SecureString& str) const
    {
      return m_base.compare(pos, n, str.m_base);
    }

    int compare(size_t pos, size_t n, const NarrowString& str) const
    {
      return m_base.compare(pos, n, SecureStringBase(str.data(), str.size()));
    }

    int compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const
    {
      return m_base.compare(pos1, n1, str.m_base, pos2, n2);
    }

    int compare(size_t pos1, size_t n1, const NarrowString& str, size_t pos2, size_t n2) const
    {
      return m_base.compare(pos1, n1, SecureStringBase(str.data(), str.size()), pos2, n2);
    }

    int compare(const Char* s) const
    {
      ASSERT(s);
      return m_base.compare(s);
    }

    int compare(size_t pos, size_t n, const Char* s) const
    {
      ASSERT(s);
      return m_base.compare(pos, n, s);
    }

    int compare(size_t pos1, size_t n1, const Char* s, size_t n2) const
    {
      ASSERT(s);
      return m_base.compare(pos1, n1, s, n2);
    }

  private:
    SecureStringBase m_base;
  }; // CLASS

  inline bool operator==(const NarrowString& s, const esapi::SecureString& ss)
  {
    return ss.compare(0, s.size(), s.data()) == 0;
  }

  inline bool operator==(const esapi::SecureString& ss, const NarrowString& s)
  {
    return ss.compare(0, s.size(), s.data()) == 0;
  }

} // NAMESPACE

// Effective C++, Item 25, pp 106-112
// Dupicate symbols
namespace std
{
  template <>
  inline void swap(esapi::SecureString& a, esapi::SecureString& b)
  {
    a.swap(b);
  }
}
