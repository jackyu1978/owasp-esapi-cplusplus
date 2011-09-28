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
#include "util/ArrayZeroizer.h"
#include "errors/InvalidArgumentException.h"

#include <iconv.h>
#include <errno.h>
#include <endian.h>

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
      if(m_cd != nullptr && m_cd != (iconv_t)-1) {
        iconv_close(m_cd);
        m_cd = (iconv_t)-1;
      }
    }
  private:
    iconv_t m_cd;
  };

  static const std::string WideEncoding = "UTF-32";
  static const unsigned int WCHAR_T_SIZE = sizeof(wchar_t);

  /**
   * Convert a narrow character string to a wide character string. Encoding specifies
   * the encoding of the narrow string. If the string is from the current locale, use
   * EncodingDefault.
   */
  String TextConvert::NarrowToWide(const NarrowString& str, const Encoding& enc)
  {
    ASSERT( !str.empty() );
    if(str.empty()) return String();    

    // Check for overflow on the reserve performed below
    WideString temp;
    if(str.length() > temp.max_size())
      throw InvalidArgumentException("TextConvert::NarrowToWide failed (1). The output buffer would overflow");

    //  Reserve it
    temp.reserve(str.length());

    iconv_t cd = iconv_open ("UTF-32", enc.c_str());
    AutoConvDesc cleanup1(cd);

    ASSERT(cd != (iconv_t)-1);
    if(cd == (iconv_t)-1)
      throw InvalidArgumentException("TextConvert::NarrowToWide failed (2). The conversion descriptor is not valid");
    
    wchar_t out[4096 / WCHAR_T_SIZE];
    ArrayZeroizer<wchar_t> cleanup2(out, COUNTOF(out));
    const size_t outbytes = sizeof(out);

    // libiconv manages inptr and inlen for each iteration
    char* inptr = (char*)&str[0];
    size_t inlen = str.length();

    while(inlen != 0)
      {
        char* outptr = (char*)&out[0];
        size_t outlen = outbytes;

        size_t nonconv = iconv(cd, &inptr, &inlen, &outptr, &outlen);
        int err = errno;

        // An invalid multibyte sequence is encountered in the input.
        ASSERT(nonconv != (size_t)-1);
        if(nonconv == (size_t)-1 && err == EILSEQ)
          {
            std::ostringstream oss;
            oss << "TextConvert::NarrowToWide failed (3, EILSEQ). An invalid multibyte character ";
            oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&str[0]);
            throw InvalidArgumentException(oss.str());
          }
      
        // An invalid multibyte sequence is encountered in the input.
        ASSERT(nonconv != (size_t)-1);
        if(nonconv == (size_t)-1 && err == EINVAL)
          {
            std::ostringstream oss;
            oss << "TextConvert::NarrowToWide failed (4, EINVAL). An invalid multibyte character ";
            oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&str[0]);
            throw InvalidArgumentException(oss.str());
          }
      
        // Failed to convert all input characters. {-1, E2BIG } is expected.
        ASSERT(nonconv == 0 || (nonconv == (size_t)-1 && err == E2BIG));
        if(!(nonconv == 0 || (nonconv == (size_t)-1 && err == E2BIG)))
          {
            std::ostringstream oss;
            oss << "TextConvert::NarrowToWide failed (5). Failed to convert a multibyte character ";
            oss << "at byte position " << (size_t)((byte*)inptr - (byte*)&str[0]);
            oss << ". Return = " << nonconv << ", errno = " << err;
            throw InvalidArgumentException(oss.str());
          }
        
        const size_t ccb = outbytes - outlen;
        if(ccb)
          {
            const wchar_t* first = out;
            const wchar_t* last = (wchar_t*)((char*)out + ccb);
            temp.append(first, last);
          }
      }

    if(temp.size() >= 1 && (temp[0] == 0xfeff || temp[0] == 0xfffe))
      temp.erase(temp.begin(), temp.begin()+1);

    WideString wstr;
    wstr.swap(temp);

    return wstr;
  }

  /**
   * Convert a wide character string to a UTF-8 character string. Used by exception classes.
   */
  NarrowString TextConvert::WideToNarrowNoThrow(const String& wstr)
  {
    // This can still throw via the string
    try
    {
      return WideToNarrow(wstr);
    }
    catch(const InvalidArgumentException&)
    {
    }

    return NarrowString("TextConvert::WideToNarrowNoThrow failed");
  }

  NarrowString TextConvert::WideToNarrow(const String& wstr, const Encoding& enc)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();    

    // Check for overflow on the reserve performed below
    NarrowString temp;
    if(wstr.length() > temp.max_size())
      throw InvalidArgumentException("TextConvert::WideToNarrow failed (1). The output buffer would overflow");

    //  Reserve it
    temp.reserve(wstr.length());

    iconv_t cd = iconv_open (enc.c_str(), "UTF-32");
    AutoConvDesc cleanup1(cd);

    ASSERT(cd != (iconv_t)-1);
    if(cd == (iconv_t)-1)
      throw InvalidArgumentException("TextConvert::WideToNarrow failed (2). The conversion descriptor is not valid");
    
    char out[4096];
    ArrayZeroizer<char> cleanup2(out, COUNTOF(out));
    const size_t outbytes = sizeof(out);

    // libiconv manages inptr and inlen for each iteration
    char* inptr = (char*)&wstr[0];
    size_t inlen = wstr.length() * WCHAR_T_SIZE;

    bool first = true;
    while(inlen != 0)
      {
        char* outptr = (char*)&out[0];
        size_t outlen = outbytes;

        size_t nonconv = iconv(cd, &inptr, &inlen, &outptr, &outlen);
        int err = errno;

        // An invalid multibyte sequence is encountered in the input.
        ASSERT(nonconv != (size_t)-1);
        if(nonconv == (size_t)-1 && err == EILSEQ)
          {
            std::ostringstream oss;
            oss << "TextConvert::WideToNarrow failed (3, EILSEQ). An invalid multibyte character ";
            oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&wstr[0]);
            throw InvalidArgumentException(oss.str());
          }
      
        // An invalid multibyte sequence is encountered in the input.
        ASSERT(nonconv != (size_t)-1);
        if(nonconv == (size_t)-1 && err == EINVAL)
          {
            std::ostringstream oss;
            oss << "TextConvert::WideToNarrow failed (4, EINVAL). An invalid multibyte character ";
            oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&wstr[0]);
            throw InvalidArgumentException(oss.str());
          }
      
        // Failed to convert all input characters. {-1, E2BIG } is expected.
        ASSERT(nonconv == 0 || (nonconv == (size_t)-1 && err == E2BIG));
        if(!(nonconv == 0 || (nonconv == (size_t)-1 && err == E2BIG)))
          {
            std::ostringstream oss;
            oss << "TextConvert::WideToNarrow failed (5). Failed to convert a multibyte character ";
            oss << "at byte position " << (size_t)((byte*)inptr - (byte*)&wstr[0]);
            oss << ". Return = " << nonconv << ", errno = " << err;
            throw InvalidArgumentException(oss.str());
          }

        const size_t ccb = outbytes - outlen;
        if(ccb)
          {
            const char* first = out;
            const char* last = (char*)((char*)out + ccb);
            temp.append(first, last);
          }
      }

    if(temp.size() >= 2 && ((temp[0] == 0xfe && temp[1] == 0xff) || (temp[0] == 0xff && temp[1] == 0xfe)))
      temp.erase(temp.begin(), temp.begin()+2);

    NarrowString nstr;
    nstr.swap(temp);

    return nstr;
  }

  SecureByteArray TextConvert::GetBytes(const String& wstr, const Encoding& enc)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return SecureByteArray();    

    // Check for overflow on the reserve performed below
    SecureByteArray temp;
    if(wstr.length() > temp.max_size())
      throw InvalidArgumentException("TextConvert::WideToNarrow failed (1). The output buffer would overflow");

    //  Reserve it
    temp.reserve(wstr.length());

    iconv_t cd = iconv_open (enc.c_str(), "UTF-32");
    AutoConvDesc cleanup1(cd);

    ASSERT(cd != (iconv_t)-1);
    if(cd == (iconv_t)-1)
      throw InvalidArgumentException("TextConvert::WideToNarrow failed (2). The conversion descriptor is not valid");
    
    char out[4096];
    ArrayZeroizer<char> cleanup2(out, COUNTOF(out));
    const size_t outbytes = sizeof(out);

    // libiconv manages inptr and inlen for each iteration
    char* inptr = (char*)&wstr[0];
    size_t inlen = wstr.length() * WCHAR_T_SIZE;

    while(inlen != 0)
      {
        char* outptr = (char*)&out[0];
        size_t outlen = outbytes;

        size_t nonconv = iconv(cd, &inptr, &inlen, &outptr, &outlen);
        int err = errno;

        // An invalid multibyte sequence is encountered in the input.
        ASSERT(nonconv != (size_t)-1);
        if(nonconv == (size_t)-1 && err == EILSEQ)
          {
            std::ostringstream oss;
            oss << "TextConvert::WideToNarrow failed (3, EILSEQ). An invalid multibyte character ";
            oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&wstr[0]);
            throw InvalidArgumentException(oss.str());
          }
      
        // An invalid multibyte sequence is encountered in the input.
        ASSERT(nonconv != (size_t)-1);
        if(nonconv == (size_t)-1 && err == EINVAL)
          {
            std::ostringstream oss;
            oss << "TextConvert::WideToNarrow failed (4, EINVAL). An invalid multibyte character ";
            oss << "was encountered at byte position " << (size_t)((byte*)inptr - (byte*)&wstr[0]);
            throw InvalidArgumentException(oss.str());
          }
      
        // Failed to convert all input characters. {-1, E2BIG } is expected.
        ASSERT(nonconv == 0 || (nonconv == (size_t)-1 && err == E2BIG));
        if(!(nonconv == 0 || (nonconv == (size_t)-1 && err == E2BIG)))
          {
            std::ostringstream oss;
            oss << "TextConvert::WideToNarrow failed (5). Failed to convert a multibyte character ";
            oss << "at byte position " << (size_t)((byte*)inptr - (byte*)&wstr[0]);
            oss << ". Return = " << nonconv << ", errno = " << err;
            throw InvalidArgumentException(oss.str());
          }

        const size_t ccb = outbytes - outlen;
        if(ccb)
          {
            const byte* first = (byte*)out;
            temp.insert(temp.end(), first, ccb);
          }     
      }

    if(temp.size() && (*temp.begin() == 0xfeff || *temp.begin() == 0xfffe))
      temp.erase(temp.begin(), temp.begin()+1);

    SecureByteArray sba;
    sba.swap(temp);

    return sba;
  }
}
