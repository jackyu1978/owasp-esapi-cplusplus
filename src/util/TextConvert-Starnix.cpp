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

#include "util/SecureArray.h"
#include "util/TextConvert.h"
#include "errors/InvalidArgumentException.h"

#if defined(ESAPI_OS_STARNIX)
# include "utfcpp/utf8.h"
#endif

namespace esapi
{
  /**
   * Convert a narrow character string to a wide character string. Encoding specifies
   * the encoding of the narrow string. If the string is from the current locale, use
   * EncodingDefault. If the narrow string is UTF-8, use EncodingNarrow.
   */
  String TextConvert::NarrowToWide(const NarrowString& str, const Encoding& enc)
  {
    ASSERT( !str.empty() );
    if(str.empty()) return String();

    WideString wstr;
    wstr.reserve(str.length());

    try
    {
      utf8::utf8to32(str.begin(), str.end(), back_inserter(wstr));
    }
    catch(const utf8::exception&)
    {
      throw InvalidArgumentException(L"TextConvert::NarrowToWide failed");
    }

    return wstr;
  }

  NarrowString TextConvert::WideToNarrow(const String& wstr, const Encoding& enc)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();

    NarrowString nstr;
    nstr.reserve(wstr.length());

    try
    {
      utf8::utf32to8(wstr.begin(), wstr.end(), back_inserter(nstr));
    }
    catch(const utf8::exception&)
    {
      throw InvalidArgumentException(L"TextConvert::WideToNarrow failed");
    }

    return nstr;
  }

  SecureByteArray TextConvert::GetBytes(const String& wstr, const Encoding& enc)
  {
    return SecureByteArray();
  }
}
