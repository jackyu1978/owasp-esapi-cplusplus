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

#include "EsapiCommon.h"
#include "crypto/PlainText.h"
#include "util/SecureArray.h"
#include "errors/EncodingException.h"
#include <algorithm>

namespace esapi
{

  PlainText::PlainText(String str) //:See catch statement below.
  {
    /*
      try
      {
      ESAPI_ASSERT2(!str.empty(), "String for PlainText cannot be null or empty.");
      //rawBytes = toUTF8(str); //:Convert to UTF-8
      }
      catch()   //:Not sure what should be the catch parameters. "UnsupportedEncodingException e" gave errors.
      {
      //logger.error(Logger.EVENT_FAILURE, "plaintext(String) CTOR failed: Can't find UTF-8 byte-encoding!", UnsupportedEncodingException);
      throw EncodingException(L"Can't find UTF-8 byte encoding!");
      }
    */
  }

  PlainText::PlainText(const esapi::SecureByteArray &b)
  {
    ESAPI_ASSERT2(!b.empty(), "Secure byte array representing PlainText cannot be null.");
    rawBytes = b;
  }

  PlainText::PlainText()
  {
  }

  String PlainText::toString() //:Commented out for same reason as first constructor.
  {
    /*
      try
      {
      String result;
      //result = toUni(rawBytes); //:Convert to Unicode
      return result;
      }
      catch()
      {
      //logger.error(Logger.EVENT_FAILURE, "PlainText.toString() failed: Can't find UTF-8 byte encoding!", UnsupportedEncodingException);
      throw EncodingException(L"Can't find UTF-8 byte encoding!");//, UnsupportedEncodingException);
      }
    */
    return L"";
  }

  esapi::SecureByteArray PlainText::asBytes()
  {
    return rawBytes;
  }

  bool PlainText::equals(PlainText obj)
  {
    if(toString() == obj.toString())
      return true;
    return false;
  }

  size_t PlainText::length()
  {
    return rawBytes.length();
  }

  void PlainText::overwrite()
  {
    rawBytes.clear();
  }

} // NAMESPACE esapi
