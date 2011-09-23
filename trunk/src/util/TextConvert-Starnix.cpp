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

#include <iconv.h>
#include <errno.h>

// I believe there's a define for this, but I'm not sure its everywhere
static const unsigned int WCHAR_T_SIZE = sizeof(wchar_t);

namespace esapi
{
  /**
   * Private class to handle iconv lifetimes
   */
  class AutoConvDesc
  {
  public:
    explicit AutoConvDesc(iconv_t& cd) : m_cd(cd) { }

    ~AutoConvDesc() {
      if(m_cd && m_cd != -1) {
        iconv_close(m_cd);
        m_cd = -1;
      }
    }
  private:
    iconv_t m_cd;
  };

  /**
   * Convert a narrow character string to a wide character string. Encoding specifies
   * the encoding of the narrow string. If the string is from the current locale, use
   * EncodingDefault.
   */
  String TextConvert::NarrowToWide(const NarrowString& str, const Encoding& enc)
  {
    ASSERT(4 == WCHAR_T_SIZE);

    ASSERT( !str.empty() );
    if(str.empty()) return String();    

    // Check for overflow on the reserve performed below
    WideString temp;
    if(str.length() > temp.max_size())
      throw InvalidArgumentException(L"TextConvert::NarrowToWide failed (1). The output buffer would overflow");

    iconv_t cd = iconv_open ("UTF-32", enc.c_str());
    AutoConvDesc cleanup(cd);

    ASSERT(cd != (iconv_t)-1);
    if(cd == (iconv_t)-1)
      throw InvalidArgumentException(L"TextConvert::NarrowToWide failed (2). The conversion descriptor is not valid");
    
    temp.reserve(str.length());
    SecureArray<wchar_t> out(4096/WCHAR_T_SIZE);

    // libiconv manages inptr for each iteration
    char* inptr = (char*)&str[0];
    size_t inlen = str.length();

    while(inlen != 0)
    {
      char* outptr = (char*)&out[0];
      size_t outlen = out.size() * WCHAR_T_SIZE;

      size_t sz = iconv(cd, &inptr, &inlen, &outptr, &outlen);
      int err = errno;

      // An invalid multibyte sequence is encountered in the input.
      if(sz == (size_t)-1 && (err == EILSEQ || err == EINVAL))
      {
        ASSERT(0);
        std::ostringstream oss;
        oss << "TextConvert::NarrowToWide failed (3). An invalid multibyte sequence ";
        oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&str[0]);
        throw InvalidArgumentException(oss.str());
      }

      else if(sz == (size_t)-1 && err == E2BIG)
      {
        ASSERT(0 == outlen % WCHAR_T_SIZE);
        temp.append(out.begin(), out.begin()+outlen);
        continue;
      }

      ASSERT(sz != (size_t)-1);
      ASSERT(0 == inlen);
      ASSERT(0 == outlen % WCHAR_T_SIZE);
      temp.append(out.begin(), out.begin()+outlen);
    }

    WideString wstr;
    wstr.swap(temp);

    return wstr;
  }

  /**
  * Convert a wide character string to a UTF-8 character string. Used by exception classes.
  */
  NarrowString TextConvert::WideToNarrowNoThrow(const String& wstr)
  {
    return NarrowString("Not yet implemented");
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
