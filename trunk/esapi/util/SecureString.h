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
    enum { npos = (size_type)-1 };

    // Construction
    SecureString();
    SecureString(const char* s);
    explicit SecureString(const std::string&);
    SecureString(const char* s, size_t n);      
    SecureString(size_t n, char c);

    template<class InputIterator>
    explicit SecureString(InputIterator begin, InputIterator end);

    // Destruction
    virtual ~SecureString() { }

    // Copy and assignment
    SecureString(const SecureString&);

    virtual SecureString& operator=(const SecureString& str);
    virtual SecureString& operator=(const std::string& str);
    virtual SecureString& operator=(const char* str);
    virtual SecureString& operator=(char c);

    virtual SecureString& operator+=(const SecureString& str);
    virtual SecureString& operator+=(const std::string& str);
    virtual SecureString& operator+=(const char* str);
    virtual SecureString& operator+=(char c);

    virtual SecureString& append(const SecureString& str);
    virtual SecureString& append(const std::string& str);
    virtual SecureString& append(const char* str);
    virtual SecureString& append(const char* str, size_t n);
    virtual SecureString& append(size_t n, char c);

    virtual SecureString& assign(const SecureString& str);
    virtual SecureString& assign(const std::string& str);
    virtual SecureString& assign(const char* str);
    virtual SecureString& assign(const char* str, size_t n);
    virtual SecureString& assign(size_t n, char c);

    virtual SecureString& insert(size_t pos, const SecureString& str);
    virtual SecureString& insert(size_t pos, const std::string& str);
    virtual SecureString& insert(size_t pos1, const std::string& str, size_t pos2, size_t n);
    virtual SecureString& insert(size_t pos1, const SecureString& str, size_t pos2, size_t n);
    virtual SecureString& insert(size_t pos, const char* s, size_t n);
    virtual SecureString& insert(size_t pos, const char* s);

    virtual const char* c_str() const;
    virtual const char* data() const;
    virtual size_type size() const;

    virtual void swap(SecureString& str);
    virtual void swap(std::string& str);

    virtual size_t find(const SecureString& str, size_t pos = 0) const;
    virtual size_t find(const std::string& str, size_t pos = 0) const;
    virtual size_t find(const char* s, size_t pos, size_t n) const;
    virtual size_t find(const char* s, size_t pos = 0) const;
    virtual size_t find(char c, size_t pos = 0) const;

    virtual size_t rfind(const SecureString& str, size_t pos = npos) const;
    virtual size_t rfind(const std::string& str, size_t pos = npos) const;
    virtual size_t rfind(const char* s, size_t pos, size_t n) const;
    virtual size_t rfind(const char* s, size_t pos = npos) const;
    virtual size_t rfind(char c, size_t pos = npos) const;

    virtual size_t find_first_of(const SecureString& str, size_t pos = 0) const;
    virtual size_t find_first_of(const std::string& str, size_t pos = 0) const;
    virtual size_t find_first_of(const char* s, size_t pos, size_t n) const;
    virtual size_t find_first_of(const char* s, size_t pos = 0) const;
    virtual size_t find_first_of(char c, size_t pos = 0) const;

    virtual size_t find_last_of(const SecureString& str, size_t pos = npos) const;
    virtual size_t find_last_of(const std::string& str, size_t pos = npos) const;
    virtual size_t find_last_of(const char* s, size_t pos, size_t n) const;
    virtual size_t find_last_of(const char* s, size_t pos = npos) const;
    virtual size_t find_last_of(char c, size_t pos = npos) const;

    virtual size_t find_first_not_of(const SecureString& str, size_t pos = 0) const;
    virtual size_t find_first_not_of(const std::string& str, size_t pos = 0) const;
    virtual size_t find_first_not_of(const char* s, size_t pos, size_t n) const;
    virtual size_t find_first_not_of(const char* s, size_t pos = 0) const;
    virtual size_t find_first_not_of(char c, size_t pos = 0) const;

    virtual size_t find_last_not_of(const SecureString& str, size_t pos = npos) const;
    virtual size_t find_last_not_of(const std::string& str, size_t pos = npos) const;
    virtual size_t find_last_not_of(const char* s, size_t pos, size_t n) const;
    virtual size_t find_last_not_of(const char* s, size_t pos = npos) const;
    virtual size_t find_last_not_of(char c, size_t pos = npos) const;

    virtual int compare(const SecureString& str) const;
    virtual int compare(size_t pos, size_t n, const SecureString& str) const;
    virtual int compare(size_t pos1, size_t n1, const SecureString& str, size_t pos2, size_t n2) const;

    virtual int compare(const std::string& str) const;
    virtual int compare(size_t pos, size_t n, const std::string& str) const;
    virtual int compare(size_t pos1, size_t n1, const std::string& str, size_t pos2, size_t n2) const;

    virtual int compare(const char* s) const;
    virtual int compare(size_t pos, size_t n, const char* s) const;
    virtual int compare(size_t pos1, size_t n1, const char* s, size_t n2) const;

  private:
    SecureStringBase m_base;
  };
}

// Believe it or not, yes we need to do it....
bool operator==(const std::string& s, const esapi::SecureString& ss);
bool operator==(const esapi::SecureString& ss, const std::string& s);
