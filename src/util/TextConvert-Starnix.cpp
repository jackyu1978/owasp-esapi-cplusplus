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

namespace esapi
{
  String TextConvert::NarrowToWide(const NarrowString& str, CodePage cp)
  {
    ASSERT( !str.empty() );
    if(str.empty()) return String();

    String wide;
    wide.assign(str.begin(), str.end());

    return wide;
  }

  NarrowString TextConvert::WideToNarrow(const String& wstr, CodePage cp)
  {
    ASSERT( !wstr.empty() );
    if(wstr.empty()) return NarrowString();

    NarrowString narrow;
    narrow.assign(str.begin(), str.end());

    return narrow;
  }

  SecureByteArray TextConvert::GetBytes(const String& wstr, CodePage cp)
  {
    return SecureByteArray();
  }
}
