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
  NarrowString LDAPCodec::encodeCharacter(const StringArray& immune, const NarrowString& ch) const {
    // ASSERT(!immune.empty());
    ASSERT(!ch.empty());

    if(ch.empty())
      return NarrowString();

    // check for immune characters
    for (size_t i=0; i<immune.size(); ++i) {
      if (immune[i] == ch)
        return ch;
    }

    switch (ch[0]) {
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
      return ch;
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
