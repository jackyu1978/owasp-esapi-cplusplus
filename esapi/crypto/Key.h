/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author kevin.w.wall@gmail.com
 * @author noloader@gmail.com
 *
 */

#pragma once

#include "EsapiCommon.h"
#include <string>

/**
 * This abstract base class mimics functionality similar to Java's Key
 * interface for consistency and easier porting from ESAPI for Java.
 */
namespace esapi
{
  class Key
  {
  public:
    /**
     * Returns the standard algorithm name for this key.
     */
    virtual std::string getAlgorithm() const = 0;

    /**
     * Returns the name of the primary encoding format of this key, or
     * an a reference to an empty string if this key does not support encoding.
     * The primary encoding format is named in terms of the appropriate ASN.1
     * data format, if an ASN.1 specification for this key exists. When no
     * encoding exists, a reference to the string "RAW" should be returned.
     */
    virtual std::string getFormat() const = 0;

    /**
     * Returns the key in its primary encoding format, or nullptr
     * if this key does not support encoding.
     */
    virtual const byte* getEncoded() const = 0;

  protected:
    virtual ~Key() { }

  private:
    // Ensure compiler never generates this. We have to have it, see
    // Miscellaneous iten 5 at http://gcc.gnu.org/faq.html.
    // virtual Key& operator=(const Key& rhs);
  };

}; // NAMESPACE esapi
