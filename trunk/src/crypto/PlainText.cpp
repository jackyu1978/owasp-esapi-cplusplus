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
    // representing the string under a UTF-8 encoding.
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

  String PlainText::toString() const //:ByteArray of [formerly] encoded string in UTF-8 -> NarrowString -> WideString result
  {
    NarrowString result(rawBytes.begin(), rawBytes.end());
    return TextConvert::NarrowToWide(result);
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
