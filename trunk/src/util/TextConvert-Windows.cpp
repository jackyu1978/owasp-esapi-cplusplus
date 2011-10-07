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
#include "util/Mutex.h"
#include "util/SecureArray.h"
#include "util/TextConvert.h"
#include "crypto/Crypto++Common.h"
#include "errors/IllegalArgumentException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>

#ifndef WC_ERR_INVALID_CHARS
# define WC_ERR_INVALID_CHARS 0x0080 
#endif

namespace esapi
{
  Mutex& GetClassLock()
  {
    static Mutex s_lock;
    return s_lock;
  }

  class icompare {
  public:
    bool operator()(std::string x, std::string y) const {
      std::transform(x.begin(), x.end(), x.begin(), tolower);
      std::transform(y.begin(), y.end(), y.begin(), tolower);
      return x < y;
    }
  };

  typedef std::map<std::string, UINT, icompare> CodePageMap;
  typedef CodePageMap::const_iterator CodePageMapInterator;
  typedef CodePageMap::value_type CodePageMapValue;

  // Lots of Code Pages on Windows. For the most part, we should support them all in this table.
  // http://msdn.microsoft.com/en-us/library/windows/desktop/dd317756(v=vs.85).aspx
  const CodePageMap& GetCodePageMap()
  {
    MutexLock lock(GetClassLock());

    static bool init = false;
    static CodePageMap map;

    MEMORY_BARRIER();
    if(!init)
      {   
        map.insert(CodePageMapValue("IBM437", 437));

        map.insert(CodePageMapValue("windows-1250", 1250));
        map.insert(CodePageMapValue("windows-1251", 1251));
        map.insert(CodePageMapValue("windows-1252", 1252));
        map.insert(CodePageMapValue("windows-1253", 1253));
        map.insert(CodePageMapValue("windows-1254", 1254));
        map.insert(CodePageMapValue("windows-1255", 1255));
        map.insert(CodePageMapValue("windows-1256", 1256));
        map.insert(CodePageMapValue("windows-1257", 1257));
        map.insert(CodePageMapValue("windows-1258", 1258));

        map.insert(CodePageMapValue("iso-8859-1", 28591));
        map.insert(CodePageMapValue("iso-8859-2", 28592));
        map.insert(CodePageMapValue("iso-8859-3", 28593));
        map.insert(CodePageMapValue("iso-8859-4", 28594));
        map.insert(CodePageMapValue("iso-8859-5", 28595));
        map.insert(CodePageMapValue("iso-8859-6", 28596));
        map.insert(CodePageMapValue("iso-8859-7", 28597));
        map.insert(CodePageMapValue("iso-8859-8", 28598));
        map.insert(CodePageMapValue("iso-8859-9", 28599));
        map.insert(CodePageMapValue("iso-8859-13", 28603));
        map.insert(CodePageMapValue("iso-8859-15", 28605));

        map.insert(CodePageMapValue("utf8", 65001));
        map.insert(CodePageMapValue("utf-8", 65001));

        init = true;
        MEMORY_BARRIER();
      }

    return map;
  }

  inline UINT EncodingToWindowsCodePage(const Encoding& encoding)
  {
    Encoding enc(encoding);

    // Cut out whitespace
    Encoding::iterator eit = std::remove_if(enc.begin(), enc.end(), ::isspace);
    if(eit != enc.end())
      enc.erase(eit, enc.end());

    Encoding trimmed(enc);

    // Treat empty as a 'default' encoding
    if(enc.empty())
      return 0;

    // See if caller specified the page directly.
    CryptoPP::Integer n(enc.c_str());
    std::ostringstream oss;
    oss << n;
    std::string nn(oss.str());

    // Trim a trailing suffix from the integer (if present)
    const size_t len = nn.length();
    if(len && !::isalnum(nn[len-1]))
      nn.erase(nn.end()-1);

    if(nn == enc)
      {
        if(n > 65001)
          {
            std::ostringstream msg;
            msg << "Encoding '" << trimmed << "' is not valid";
            throw IllegalArgumentException(msg.str());
          }
        return (UINT)n.ConvertToLong();
      }

    const CodePageMap& cpm = GetCodePageMap();
    if(0 == cpm.count(enc))
      {
        std::ostringstream msg;
        msg << "Encoding '" << trimmed << "' is not valid";
        throw IllegalArgumentException(msg.str());
      }

    CodePageMapInterator fit = cpm.find(enc);
    ASSERT(fit != cpm.end());
    return fit->second;
  }

  String TextConvert::NarrowToWide(const NarrowString& str, const Encoding& enc)
  {
    ASSERT( !str.empty() );
    if(str.empty()) return String();

    const UINT cpage = EncodingToWindowsCodePage(enc);
    static const DWORD dwFlags = MB_ERR_INVALID_CHARS;

    try
      {
        SafeInt<size_t> sz(str.size());
        INT dw = (INT)sz;
        UNUSED_VARIABLE(dw);
      }
    catch(SafeIntException&)
      {
        throw IllegalArgumentException("TextConvert::NarrowToWide: string is too large");
      }

    DWORD dwReq = MultiByteToWideChar(cpage, dwFlags, str.data(), (INT)str.size(), NULL, 0);
    ASSERT(dwReq > 0);
    if( !(dwReq > 0) )
      throw IllegalArgumentException("TextConvert::NarrowToWide failed (1)");

    SecureArray<wchar_t> arr(dwReq);
    DWORD dwWritten = MultiByteToWideChar(cpage, dwFlags, str.data(), (INT)str.size(), (LPWSTR)arr.data(), (INT)arr.size());
    ASSERT(dwReq == dwWritten);
    if(dwReq != dwWritten)
      throw IllegalArgumentException("TextConvert::NarrowToWide failed (2)");

    return String(arr.begin(), arr.end());
  }

  NarrowString TextConvert::WideToNarrow(const String& wstr, const Encoding& enc)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();

    SecureByteArray arr = GetBytes(wstr, enc);
    return NarrowString(arr.begin(), arr.end());
  }

  /**
   * Convert a wide character string to a UTF-8 character string. Used by exception classes.
   */
  NarrowString TextConvert::WideToNarrowNoThrow(const String& wstr)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();

    try
      {
        SafeInt<size_t> sz(wstr.size());
        INT dw = (INT)sz;
        UNUSED_VARIABLE(dw);
      }
    catch(SafeIntException&) {
      return NarrowString("TextConvert::WideToNarrowNoThrow: message string is too large (1)");
    }

    const DWORD dwFlags = WC_ERR_INVALID_CHARS | WC_NO_BEST_FIT_CHARS;

    // If the function succeeds and cbMultiByte is 0, the return value is the required size, in bytes,
    // for the buffer indicated by lpMultiByteStr.
    DWORD dwReq = WideCharToMultiByte(CP_UTF8, dwFlags, wstr.data(), (INT)wstr.size(), NULL, 0, NULL, NULL);
    ASSERT(dwReq > 0);
    if( !(dwReq > 0) )
      return NarrowString("TextConvert::WideToNarrowNoThrow failed (1)");

    try
      {
        SafeInt<size_t> sz(dwReq);
        INT dw = (INT)sz;
        UNUSED_VARIABLE(dw);
      }
    catch(SafeIntException&) {
      return NarrowString("TextConvert::WideToNarrowNoThrow: message string is too large (2)");
    }

    SecureByteArray arr(dwReq);

    // Returns the number of bytes written to the buffer pointed to by lpMultiByteStr if successful.    
    DWORD dwWritten = WideCharToMultiByte(CP_UTF8, dwFlags, wstr.data(), (INT)wstr.size(), (LPSTR)arr.data(), (INT)arr.size(), NULL, NULL);
    ASSERT(dwWritten == dwReq);
    if(dwWritten != dwReq)
      return NarrowString("TextConvert::WideToNarrowNoThrow failed (2)");

    // WideCharToMultiByte does not null-terminate an output string if the input string length is explicitly
    // specified without a terminating null character.
    return NarrowString(arr.begin(), arr.end());
  }

  SecureByteArray TextConvert::GetBytes(const String& wstr, const Encoding& enc)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return SecureByteArray();

    try
      {
        SafeInt<size_t> sz(wstr.size());
        INT dw = (INT)sz;
        UNUSED_VARIABLE(dw);
      }
    catch(SafeIntException&)
      {
        throw IllegalArgumentException("TextConvert::GetBytes: string is too large");
      }

    const UINT cpage = EncodingToWindowsCodePage(enc);
    const bool MustBeZero = (65001  == cpage || 42 == cpage || 50220 == cpage || 50221 == cpage ||
      50222 == cpage ||  50225 == cpage || 50227 == cpage || 50229 == cpage || (cpage >= 57002 &&
      cpage <= 57011) || 65000 == cpage || 54936  == cpage);    

    // If the function succeeds and cbMultiByte is 0, the return value is the required size, in bytes,
    // for the buffer indicated by lpMultiByteStr.
    const DWORD dwFlags = (MustBeZero ? 0 : WC_ERR_INVALID_CHARS | WC_NO_BEST_FIT_CHARS);
    DWORD dwReq = WideCharToMultiByte(cpage, dwFlags, wstr.data(), (INT)wstr.size(), NULL, 0, NULL, NULL);
    ASSERT(dwReq > 0);
    if( !(dwReq > 0) )
      throw IllegalArgumentException("TextConvert::GetBytes failed (1)");

    SecureByteArray arr(dwReq);

    // Returns the number of bytes written to the buffer pointed to by lpMultiByteStr if successful.    
    DWORD dwWritten = WideCharToMultiByte(cpage, dwFlags, wstr.data(), (INT)wstr.size(), (LPSTR)arr.data(), (INT)arr.size(), NULL, NULL);
    ASSERT(dwWritten == dwReq);
    if(dwWritten != dwReq)
      throw IllegalArgumentException("TextConvert::GetBytes failed (2)");

    // WideCharToMultiByte does not null-terminate an output string if the input string length is explicitly
    // specified without a terminating null character.
    return arr;
  }
}
