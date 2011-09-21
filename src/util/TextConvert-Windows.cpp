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

#ifndef WC_ERR_INVALID_CHARS
# define WC_ERR_INVALID_CHARS 0x0080 
#endif

namespace esapi
{
  inline UINT CopePageToWindowsCodePage(TextConvert::CodePage cp)
  {
    UINT cpage = cp;
    switch(cp)
    {
    case TextConvert::CodePageDefault: cpage = 0; break;
    case TextConvert::CodePageUTF7: cpage = CP_UTF7; break;
    case TextConvert::CodePageUTF8: cpage = CP_UTF8; break;
    default:
      ASSERT(0);
    }

    return cpage;
  }

  String TextConvert::NarrowToWide(const NarrowString& str, CodePage cp)
  {
    ASSERT( !str.empty() );
    if(str.empty()) return String();

    const UINT cpage = CopePageToWindowsCodePage(cp);
    static const DWORD dwFlags = MB_ERR_INVALID_CHARS;

    DWORD dwReq = MultiByteToWideChar(cpage, dwFlags, str.data(), str.size(), NULL, 0);
    ASSERT(dwReq > 0);
    if( !(dwReq > 0) )
      throw InvalidArgumentException(L"TextConvert::NarrowToWide failed (1)");

    SecureArray<wchar_t> arr(dwReq);
    DWORD dwWritten = MultiByteToWideChar(cpage, dwFlags, str.data(), str.size(), (LPWSTR)arr.data(), (INT)arr.size());
    ASSERT(dwReq == dwWritten);
    if(dwReq != dwWritten)
      throw InvalidArgumentException(L"TextConvert::NarrowToWide failed (2)");

    return String(arr.begin(), arr.end());
  }

  NarrowString TextConvert::WideToNarrow(const String& wstr, CodePage cp)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();

    SecureByteArray arr = GetBytes(wstr, cp);
    return NarrowString(arr.begin(), arr.end());
  }

  SecureByteArray TextConvert::GetBytes(const String& wstr, CodePage cp)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return SecureByteArray();

    const UINT cpage = CopePageToWindowsCodePage(cp);
    static const DWORD dwFlags = WC_ERR_INVALID_CHARS | WC_NO_BEST_FIT_CHARS;

    DWORD dwReq = WideCharToMultiByte(cpage, dwFlags, wstr.data(), wstr.size(), NULL, 0, NULL, NULL);
    ASSERT(dwReq > 0);
    if( !(dwReq > 0) )
      throw InvalidArgumentException(L"TextConvert::GetBytes failed (1)");

    SecureByteArray arr(dwReq);
    DWORD dwWritten = WideCharToMultiByte(cpage, dwFlags, wstr.data(), wstr.size(), (LPSTR)arr.data(), (INT)arr.size(), NULL, NULL);
    ASSERT(dwWritten == dwReq);
    if(dwWritten != dwReq)
      throw InvalidArgumentException(L"TextConvert::GetBytes failed (2)");

    return arr;
  }
}
