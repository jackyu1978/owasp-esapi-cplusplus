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

  PlainText::PlainText(String str)
  {
    ASSERT(!str.empty());
    rawBytes = TextConvert::GetBytes(str);
  }

  PlainText::PlainText(const esapi::SecureByteArray &b)
  {
    rawBytes = b;
  }

  PlainText::PlainText()
  {
  }

  String PlainText::toString()
  {
    String result(rawBytes.begin(), rawBytes.end());
    return result;
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
  for(size_t i = 0; i < rawBytes.length(); i++)
     rawBytes[i] = L'*';
  }

} // NAMESPACE esapi
