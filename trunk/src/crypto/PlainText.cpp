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
#include "util/TextConvert.h"
#include <algorithm>

namespace esapi
{

  PlainText::PlainText(const String& str)
  : rawBytes()
  {
    ASSERT(!str.empty());
    // This actually calls GetBytes(str, "UTF-8"). So the SecureArray is an array
    // represnting the string under a UTF-8 encoding.
    rawBytes = TextConvert::GetBytes(str);
  }

  PlainText::PlainText(const SecureByteArray &b)
  : rawBytes(b)
  {    
  }

  PlainText::PlainText()
  : rawBytes()
  {
  }

  String PlainText::toString() const
  {
    // This is close, but not quite right. rawBytes is an array which consists of the
    // [formerly] encoded string in UTF-8. You will need to do something else before
    // stuffing it into a String. A good place to look would be TextConvertTest.cpp
    String result(rawBytes.begin(), rawBytes.end());
    return result;
  }

  SecureByteArray PlainText::asBytes() const
  {
    return SecureByteArray(rawBytes);
  }

  bool PlainText::equals(const PlainText& obj) const
  {
    // Check this!!! 
    if(toString() == obj.toString())
      return true;
    return false;
  }

  size_t PlainText::length() const
  {
    return rawBytes.length();
  }

  void PlainText::overwrite()
  {
    for(size_t i = 0; i < rawBytes.length(); i++)
      rawBytes[i] = '*';
  }

} // NAMESPACE esapi
