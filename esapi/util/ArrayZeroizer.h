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

namespace esapi
{
  // Used for arrays which need zeroizing. E.g.,
  //  byte buffer[200];
  //  ByteArrayZeroizer zz(buffer, sizeof(buffer));

  template<class T>
  class ArrayZeroizer
  {
  public:
    static volatile void* g_dummy;

  public:
    // Attach to an array of type T and countof(T)
    explicit ArrayZeroizer(T* t, size_t c)
      : m_t(t), m_c(c) { }

    virtual ~ArrayZeroizer() {
      ::memset(m_t, 0x00, m_c * sizeof(T));
      g_dummy = m_t;
    }   

  private:
    ArrayZeroizer(const ArrayZeroizer&) { }
    ArrayZeroizer& operator=(const ArrayZeroizer&) { }

  private:
    T* m_t;
    size_t m_c;
  };

  template<class T>
  volatile void* ArrayZeroizer<T>::g_dummy = nullptr;

  typedef ArrayZeroizer<char> CharArrayZeroizer;
  typedef ArrayZeroizer<byte> ByteArrayZeroizer;
  typedef ArrayZeroizer<int> IntArrayZeroizer;
}
