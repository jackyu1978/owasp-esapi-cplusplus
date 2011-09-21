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

#pragma once

#include "EsapiCommon.h"
#include "util/SecureArray.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

#include <string>

/**
 * This abstract base class mimics functionality similar to Java's Key
 * interface for consistency and easier porting from ESAPI for Java.
 */
namespace esapi
{
  class ESAPI_TEST_EXPORT Key
  {
  public:
    /**
     * Returns the standard algorithm name for this key.
     */
    virtual String getAlgorithm() const = 0;

    /**
     * Returns the name of the primary encoding format of this key, or
     * an a reference to an empty string if this key does not support encoding.
     * The primary encoding format is named in terms of the appropriate ASN.1
     * data format, if an ASN.1 specification for this key exists. When no
     * encoding exists, a reference to the string "RAW" should be returned.
     */
    virtual String getFormat() const = 0;

    /**
     * Returns the key in its primary encoding format, or an empty array
     * if this key does not support encoding.
     */
    virtual SecureByteArray getEncoded() const = 0;

  protected:
    Key() { /* no public instantiations */ }

    virtual ~Key() { }

  };

}; // NAMESPACE esapi
