/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "EsapiCommon.h"
#include "codecs/DB2Codec.h"
#include "codecs/Codec.h"
#include "EsapiCommon.h"

namespace esapi
{
  NarrowString DB2Codec::encodeCharacter( const Char immune[], size_t length, Char c) const {
    ASSERT (c != 0);

    if (c == '\'')
      return NarrowString("\'\'");

    if (c == ';')
      return NarrowString(".");

    return NarrowString(1,c);
  }

  NarrowString DB2Codec::decodeCharacter( PushbackString& input) const {
    input.mark();
    NarrowString first(1,input.next());

    if (first.empty()) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null

    if (first[0] != '\'') {
      input.reset();
      return NarrowString();
    }

    NarrowString second(1,input.next());

    if (second.empty()) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null
    if (second[0] != '\'') {
      input.reset();
      return NarrowString();
    }

    return NarrowString("'");
  }
} // esapi
