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
 * @author Andrew Durkin, atdurkin@gmail.com
 *
 */

#pragma once

#include "EsapiCommon.h"
#include "util/SecureString.h"
#include "util/SecureArray.h"
//#include "Logger.h"

/**
 * A class representing plaintext (versus ciphertext) as related to
 * cryptographic systems. This class embodies UTF-8 byte-encoding to
 * translate between byte arrays and {@code String}s. Once constructed, this
 * object is immutable.
 **/

namespace esapi
{

  class ESAPI_EXPORT PlainText
  {
  private:
    //const Logger logger = esapi.getLogger("PlainText");  //:Logger not implemented yet.
    SecureByteArray rawBytes; //:Plaintext stored as byte array.
  public:
    PlainText();//:Preventing some errors from before.
    explicit PlainText(const String& str); //:Constructs a PlainText object using @param str. @param str is converted to UTF-8 and stored in a byte array.
    explicit PlainText(const SecureByteArray &b); //:Constructs a PlainText object from a byte array.

    // String is UTF-32 on *nix, UTF-16 on Windows.
    String toString() const; //:Converts object to UTF-8 encoded {@code String}.

    SecureByteArray asBytes() const; //:Converts object to a byte array.
    bool equals(const PlainText& obj) const;
    size_t length() const;
    void overwrite(); //:Overwrites contents of rawBytes member with '*' character.
  };
} // NAMESPACE esapi

