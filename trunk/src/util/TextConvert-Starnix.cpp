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

#include <locale>
#include <sstream>
#include <algorithm>

namespace esapi
{
  inline std::string CodePageToLocale(TextConvert::CodePage cp)
  {
    std::string loc;
    switch(cp)
    {
    case TextConvert::CodePageDefault: loc = ""; break;
    case TextConvert::CodePageUTF7: loc = "UTF-7"; break;
    case TextConvert::CodePageUTF8: loc = "UTF-8"; break;
    default:
      ASSERT(0);
    }

    return loc;
  }

  String TextConvert::NarrowToWide(const NarrowString& str, CodePage cp)
  {
    ASSERT( !str.empty() );
    if(str.empty()) return String();

    typedef std::codecvt_byname<wchar_t, char, std::mbstate_t> Cvt;
    static const std::locale utf16 (std::locale ("C"), new Cvt ("UTF-16")); 

    std::istringstream iss(str);
    std::wostringstream oss;

    oss.imbue(utf16);
    oss << iss.rdbuf();

    return oss.str();
  }

  NarrowString TextConvert::WideToNarrow(const String& wstr, CodePage cp)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();

    NarrowString narrow;
    narrow.assign(wstr.begin(), wstr.end());

    return narrow;
  }

  SecureByteArray TextConvert::GetBytes(const String& wstr, CodePage cp)
  {
    return SecureByteArray();
  }
}
