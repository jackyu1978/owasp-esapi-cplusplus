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
#include "codecs/LDAPCodec.h"
#include "codecs/Codec.h"

namespace esapi
{
  String LDAPCodec::encodeCharacter( const Char immune[], size_t length, Char c) const {
    ASSERT(immune);
    ASSERT(length);
    ASSERT (c != 0);

    // check for immune characters
    if(immune)
      {
	for (unsigned int i=0; i<length; i++) {
	  if (immune[i] == c)
	    return String(1, c);
	}
      }

    switch (c) {
    case '\\':
      return "\\5c";
      break;
    case '*':
      return "\\2a";
      break;
    case '(':
      return "\\28";
      break;
    case ')':
      return "\\29";
      break;
    case '\0':
      return "\\00";
      break;
    default:
      return String(1, c);
    }
  }

  NarrowString LDAPCodec::decodeCharacter(PushbackString& input) const {
    ASSERT(input.hasNext());

    input.mark();
    NarrowString first(1, input.next());
    if ( first.empty() ) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null
    if ( first[0] != '\\' ) {
      input.reset();
      return NarrowString();
    }

    return NarrowString(1,input.next());
  }
} // esapi
