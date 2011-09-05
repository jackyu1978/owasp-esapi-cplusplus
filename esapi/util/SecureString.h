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
//typedef __gnu_debug::basic_string< char, std::char_traits<char>, esapi::zallocator<char> > SecureStringBase;
//#else
//typedef std::basic_string< char, std::char_traits<char>, esapi::zallocator<char> > SecureStringBase;
//#endif

namespace esapi
{
  class ESAPI_EXPORT SecureString
  {
  public:

    typedef std::basic_string< char, std::char_traits<char>, esapi::zallocator<char> > SecureStringBase;
    typedef zallocator<char>::size_type size_type;
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
    SecureString(const char* s);
    explicit SecureString(const std::string&);
    SecureString(const char* s, size_t n);
    SecureString(const byte* b, size_t n);
    SecureString(size_t n, char c);

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
    SecureString& operator=(const std::string& str);
    SecureString& operator=(const char* str);
    SecureString& operator=(char c);

    SecureString& operator+=(const SecureString& str);
    SecureString& operator+=(const std::string& str);
    SecureString& operator+=(const char* str);
    SecureString& operator+=(char c);

    // Member functions
    SecureString& append(const SecureString& str);
    SecureString& append(const std::string& str);
    SecureString& append(const char* str);
    SecureString& append(const char* str, size_t n);
    SecureString& append(const byte* bin, size_t n);
    SecureString& append(size_t n, char c);

    SecureString& assign(const SecureString& str);
    SecureString& assign(const std::string& str);
    SecureString& assign(const char* str);
    SecureString& assign(const char* str, size_t n);
    SecureString& assign(const byte* bin, size_t n);
    SecureString& assign(size_t n, char c);

    SecureString& insert(size_t pos, const SecureString& str);
    SecureString& insert(size_t pos, const std::string& str);
    SecureString& insert(size_t pos1, const std::string& str, size_t pos2, size_t n);
    SecureString& insert(size_t pos1, const SecureString& str, size_t pos2, size_t n);
    SecureString& insert(size_t pos, const char* s, size_t n);
    SecureString& insert(size_t pos, const byte* b, size_t n);
    SecureString& insert(size_t pos, const char* s);

    SecureString& erase(size_t pos = 0, size_t n = npos);
    iterator erase(iterator position );
    iterator erase(iterator first, iterator last);

    const char& operator[] ( size_t pos ) const;
    char& operator[] ( size_t pos );
    const char& at(size_t pos) const;
    char& at(size_t pos);

    const char* c_str() const;
    const char* data() const;

    void swap(SecureString& str);

    size_t find(const SecureString& str, size_t pos = 0) const;
    size_t find(const std::string& str, size_t pos = 0) const;
    size_t find(const char* s, size_t pos, size_t n) const;
    size_t find(const char* s, size_t pos = 0) const;
    size_t find(char c, size_t pos = 0) const;

    size_t rfind(const SecureString& str, size_t pos = npos) const;
    size_t rfind(const std::string& str, size_t pos = npos) const;
    size_t rfind(const char* s, size_t pos, size_t n) const;
    size_t rfind(const char* s, size_t pos = npos) const;
    size_t rfind(char c, size_t pos = npos) const;

    size_t find_first_of(const SecureString& str, size_t pos = 0) const;
    size_t find_first_of(const std::string& str, size_t pos = 0) const;
    size_t find_first_of(const char* s, size_t pos, size_t n) const;
    size_t find_first_of(const char* s, size_t pos = 0) const;
    size_t find_first_of(char c, size_t pos = 0) const;

    size_t find_last_of(const SecureString& str, size_t pos = npos) const;
    size_t find_last_of(const std::string& str, size_t pos = npos) const;
    size_t find_last_of(const char* s, size_t pos, size_t n) const;
    size_t find_last_of(const char* s, size_t pos = npos) const;
    size_t find_last_of(char c, size_t pos = npos) const;

    size_t find_first_not_of(const SecureString& str, size_t pos = 0) const;
    size_t find_first_not_of(const std::string& str, size_t pos = 0) const;
    size_t find_first_not_of(const char* s, size_t pos, size_t n) const;
    size_t find_first_not_of(const char* s, size_t pos = 0) const;
    size_t find_first_not_of(char c, size_t pos = 0) const;

    size_t find_last_not_of(const SecureString& str, size_t pos = npos) const;
    size_t find_last_not_of(const std::string& str, size_t pos = npos) const;
    size_t find_last_not_of(const char* s, size_t pos, size_t n) const;
    size_t find_last_not_of(const char* s, size_t pos = npos) const;
    size_t find_last_not_of(char c, size_t pos = npos) const;

    int compare(const SecureString& str) const;
    int compare(size_t pos, size_t n, const SecureString& str) const;
    int compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const;

    int compare(const std::string& str) const;
    int compare(size_t pos, size_t n, const std::string& str) const;
    int compare(size_t pos1, size_t n1, const std::string& str, size_t pos2, size_t n2) const;

    int compare(const char* s) const;
    int compare(size_t pos, size_t n, const char* s) const;
    int compare(size_t pos1, size_t n1, const char* s, size_t n2) const;

  private:
    SecureStringBase m_base;
  };
} // NAMESPACE

// Effective C++, Item 25, pp 106-112
namespace std
{
  template <>
  void swap(esapi::SecureString& a, esapi::SecureString& b);
}

bool operator==(const std::string& s, const esapi::SecureString& ss);
bool operator==(const esapi::SecureString& ss, const std::string& s);
