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

#include "EsapiCommon.h"
#include "util/NotCopyable.h"
#include "util/SecureArray.h"

namespace esapi
{
  class TextConvert : private NotCopyable
  {
  public:
    enum CodePage { CodePageDefault = -1, CodePageUTF7 = -7, CodePageUTF8 = -8 };
    /**
    * Convert a narrow character string to a wide character string
    */
    static String NarrowToWide(const NarrowString& str, CodePage cp = CodePageDefault);
    /**
    * Convert a wide character string to a narrow character string
    */
    static NarrowString WideToNarrow(const String& wstr, CodePage cp = CodePageDefault);
    /**
    * Convert a wide character string to a byte array
    */
    static SecureByteArray GetBytes(const String& wstr, CodePage cp = CodePageUTF8);
  };
}
