/**
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

#include "crypto/IvParameterSpec.h"
#include "errors/IllegalArgumentException.h"

#include "safeint/SafeInt3.hpp"

namespace esapi
{
  /**
  * Creates an IvParameterSpec object using the bytes in iv as the IV.
  */
  IvParameterSpec::IvParameterSpec(const byte iv[], size_t size)
    : m_parameter(iv, size)
  {
    ASSERT(iv);
    ASSERT(size);
  }

  /**
  * Creates an IvParameterSpec object using the bytes in iv as the IV.
  */
  IvParameterSpec::IvParameterSpec(const SecureByteArray& iv)
    : m_parameter(iv.data(), iv.size())
  {
    ASSERT(iv.data());
    ASSERT(iv.size());
  }

  /**
  * Creates an IvParameterSpec object using the first len bytes in iv,
  * beginning at offset inclusive, as the IV.
  */
  IvParameterSpec::IvParameterSpec(const byte iv[], size_t size, size_t offset, size_t len)
    : m_parameter()
  {
    ESAPI_ASSERT2(iv, "Iv is not valid");
    ESAPI_ASSERT2(size, "Iv size is 0");
    ESAPI_ASSERT2(len, "Length is 0");
    ESAPI_ASSERT2(len <= size, "Length exceeds iv size");
    ESAPI_ASSERT2(offset <= size - len, "Offset and length exceed iv array size");

    try
    {
      SafeInt<size_t> si(offset);
      si += len;

      if((size_t)si > size)
        throw IllegalArgumentException("The iv array is too small for the specified offset and length");

      SecureByteArray sa(&(iv[offset]), len);
      m_parameter.swap(sa);
    }
    catch(const SafeIntException&)
    {
      throw IllegalArgumentException("Integer overflow detected");
    }
  }

  /**
  * Creates an IvParameterSpec object using the first len bytes in iv,
  * beginning at offset inclusive, as the IV.
  */
  IvParameterSpec::IvParameterSpec(const SecureByteArray& iv, size_t offset, size_t len)
    : m_parameter()
  {
    ESAPI_ASSERT2(iv.data(), "Iv is not valid");
    ESAPI_ASSERT2(iv.size(), "Iv size is 0");
    ESAPI_ASSERT2(len, "Length is 0");
    ESAPI_ASSERT2(len <= iv.size(), "Length exceeds iv size");
    ESAPI_ASSERT2(offset <= iv.size() - len, "Offset and length exceed iv array size");

    try
    {
      SafeInt<size_t> si(offset);
      si += len;

      if((size_t)si > iv.size())
        throw IllegalArgumentException("The iv array is too small for the specified offset and length");

      SecureByteArray sa(&(iv.data()[offset]), len);
      m_parameter.swap(sa);
    }
    catch(const SafeIntException&)
    {
      throw IllegalArgumentException("Integer overflow detected");
    }
  }

} // NAMESPACE
