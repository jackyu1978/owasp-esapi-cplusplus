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
 * @author Daniel Amodio, dan.amodio@aspectsecurity.com
 * @author Andrew Durkin, atdurkin@gmail.com
 *
 */

#pragma once

#include "EsapiCommon.h"
#include "util/NotCopyable.h"
#include "util/SecureArray.h"

namespace esapi
{
  typedef NarrowString Encoding;

  class ESAPI_EXPORT TextConvert : private NotCopyable
  {
  public:
    /**
    * Convert a narrow character string to a wide character string. Encoding specifies
    * the encoding of the narrow string. If the string is from the current locale, use
    * EncodingDefault. If the narrow string is UTF-8, use EncodingNarrow.
    */
    static WideString NarrowToWide(const NarrowString& str, const Encoding& encoding = "UTF-8");
    /**
    * Convert a wide character string to a narrow character string. Encoding specifies
    * the encoding of the resulting narrow string. If the current locale is desired,
    * use EncodingDefault. If UTF-8 is desired, use EncodingNarrow.
    */
    static NarrowString WideToNarrow(const WideString& wstr, const Encoding& encoding = "UTF-8");
    /**
    * Convert a wide character string to a UTF-8 character string. Used by exception classes.
    */
    static NarrowString WideToNarrowNoThrow(const WideString& wstr);
    /**
    * Convert a wide character string into a byte array using the specified encoding.
    */
    static SecureByteArray GetBytes(const NarrowString& str, const Encoding& encoding = "UTF-8");
    /**
    * Convert a wide character string into a byte array using the specified encoding.
    */
    static SecureByteArray GetBytes(const WideString& wstr, const Encoding& encoding = "UTF-8");
  };
}

