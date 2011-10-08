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

#pragma once

#include "EsapiCommon.h"
#include "util/SecureArray.h"
#include "crypto/AlgorithmParameterSpec.h"

namespace esapi
{
  class ESAPI_EXPORT IvParameterSpec: public AlgorithmParameterSpec
  {
  public:
    /**
    * Creates an IvParameterSpec object using the bytes in iv as the IV.
    */
    explicit IvParameterSpec(const byte iv[], size_t size);

    /**
    * Creates an IvParameterSpec object using the bytes in iv as the IV.
    */
    explicit IvParameterSpec(const SecureByteArray& iv);

    /**
    * Creates an IvParameterSpec object using the first len bytes in iv,
    * beginning at offset inclusive, as the IV.
    */
    explicit IvParameterSpec(const byte iv[], size_t size, size_t offset, size_t len);

    /**
    * Creates an IvParameterSpec object using the first len bytes in iv,
    * beginning at offset inclusive, as the IV.
    */
    explicit IvParameterSpec(const SecureByteArray& iv, size_t offset, size_t len);

  private:
    SecureByteArray m_parameter;
  };
} // NAMESPACE
