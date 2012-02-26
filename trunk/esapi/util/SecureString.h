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
    SecureString();
    SecureString(const Char* s);
    explicit SecureString(const String&);
    SecureString(const Char* s, size_t n);
    SecureString(const byte* b, size_t n);
    SecureString(size_t n, Char c);

    template<class InputIterator>
    explicit SecureString(InputIterator begin, InputIterator end);

    // Destruction
    ~SecureString() { }

    // Iterators
    iterator begin();
    const_iterator begin() const;

    iterator end();
    const_iterator end() const;

    reverse_iterator rbegin();
    const_reverse_iterator rbegin() const;

    reverse_iterator rend();
    const_reverse_iterator rend() const;

    // Size and capacity
    size_type max_size() const;
    size_t capacity() const;
    void reserve(size_t cnt = 0);

    bool empty() const;
    size_type length() const;
    size_type size() const;

    void clear();

    // Copy and assignment
    SecureString(const SecureString&);

    SecureString& operator=(const SecureString& str);
    SecureString& operator=(const String& str);
    SecureString& operator=(const Char* str);
    SecureString& operator=(Char c);

    SecureString& operator+=(const SecureString& str);
    SecureString& operator+=(const String& str);
    SecureString& operator+=(const Char* str);
    SecureString& operator+=(Char c);

    // Member functions
    SecureString& append(const SecureString& str);
    SecureString& append(const String& str);
    SecureString& append(const Char* str);
    SecureString& append(const Char* str, size_t n);
    SecureString& append(const byte* bin, size_t n);
    SecureString& append(size_t n, Char c);

    SecureString& assign(const SecureString& str);
    SecureString& assign(const String& str);
    SecureString& assign(const Char* str);
    SecureString& assign(const Char* str, size_t n);
    SecureString& assign(const byte* bin, size_t n);
    SecureString& assign(size_t n, Char c);

    SecureString& insert(size_t pos, const SecureString& str);
    SecureString& insert(size_t pos, const String& str);
    SecureString& insert(size_t pos1, const String& str, size_t pos2, size_t n);
    SecureString& insert(size_t pos1, const SecureString& str, size_t pos2, size_t n);
    SecureString& insert(size_t pos, const Char* s, size_t n);
    SecureString& insert(size_t pos, const byte* b, size_t n);
    SecureString& insert(size_t pos, const Char* s);

    SecureString& erase(size_t pos = 0, size_t n = npos);
    iterator erase(iterator position );
    iterator erase(iterator first, iterator last);

    const Char& operator[] ( size_t pos ) const;
    Char& operator[] ( size_t pos );
    const Char& at(size_t pos) const;
    Char& at(size_t pos);

    const Char* c_str() const;
    const Char* data() const;

    void swap(SecureString& str);

    size_t find(const SecureString& str, size_t pos = 0) const;
    size_t find(const String& str, size_t pos = 0) const;
    size_t find(const Char* s, size_t pos, size_t n) const;
    size_t find(const Char* s, size_t pos = 0) const;
    size_t find(Char c, size_t pos = 0) const;

    size_t rfind(const SecureString& str, size_t pos = npos) const;
    size_t rfind(const String& str, size_t pos = npos) const;
    size_t rfind(const Char* s, size_t pos, size_t n) const;
    size_t rfind(const Char* s, size_t pos = npos) const;
    size_t rfind(Char c, size_t pos = npos) const;

    size_t find_first_of(const SecureString& str, size_t pos = 0) const;
    size_t find_first_of(const String& str, size_t pos = 0) const;
    size_t find_first_of(const Char* s, size_t pos, size_t n) const;
    size_t find_first_of(const Char* s, size_t pos = 0) const;
    size_t find_first_of(Char c, size_t pos = 0) const;

    size_t find_last_of(const SecureString& str, size_t pos = npos) const;
    size_t find_last_of(const String& str, size_t pos = npos) const;
    size_t find_last_of(const Char* s, size_t pos, size_t n) const;
    size_t find_last_of(const Char* s, size_t pos = npos) const;
    size_t find_last_of(Char c, size_t pos = npos) const;

    size_t find_first_not_of(const SecureString& str, size_t pos = 0) const;
    size_t find_first_not_of(const String& str, size_t pos = 0) const;
    size_t find_first_not_of(const Char* s, size_t pos, size_t n) const;
    size_t find_first_not_of(const Char* s, size_t pos = 0) const;
    size_t find_first_not_of(Char c, size_t pos = 0) const;

    size_t find_last_not_of(const SecureString& str, size_t pos = npos) const;
    size_t find_last_not_of(const String& str, size_t pos = npos) const;
    size_t find_last_not_of(const Char* s, size_t pos, size_t n) const;
    size_t find_last_not_of(const Char* s, size_t pos = npos) const;
    size_t find_last_not_of(Char c, size_t pos = npos) const;

    int compare(const SecureString& str) const;
    int compare(size_t pos, size_t n, const SecureString& str) const;
    int compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const;

    int compare(const String& str) const;
    int compare(size_t pos, size_t n, const String& str) const;
    int compare(size_t pos1, size_t n1, const String& str, size_t pos2, size_t n2) const;

    int compare(const Char* s) const;
    int compare(size_t pos, size_t n, const Char* s) const;
    int compare(size_t pos1, size_t n1, const Char* s, size_t n2) const;

  private:
    SecureStringBase m_base;
  };

  ESAPI_EXPORT bool operator==(const String& s, const esapi::SecureString& ss);
  ESAPI_EXPORT bool operator==(const esapi::SecureString& ss, const String& s);

} // NAMESPACE

// Effective C++, Item 25, pp 106-112
namespace std
{
  template <>
  ESAPI_EXPORT void swap(esapi::SecureString& a, esapi::SecureString& b);
}