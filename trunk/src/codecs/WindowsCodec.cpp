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
#include "codecs/WindowsCodec.h"
#include "codecs/Codec.h"

namespace esapi
{
  NarrowString WindowsCodec::encodeCharacter(const StringArray& immune, const NarrowString& ch) const {
    // // ASSERT(!immune.empty());
    ASSERT(!ch.empty());

    // check for immune characters
    for (size_t i=0; i<immune.size(); i++) {
      if (immune[i] == ch)
        return ch;
    }

    // check for alphanumeric characters
    NarrowString hex = Codec::getHexForNonAlphanumeric( ch );
    if ( hex.empty() ) {
      return ch;
    }

    return NarrowString("^") + ch;
  }

  NarrowString WindowsCodec::decodeCharacter(PushbackString& input) const {
    input.mark();
    NarrowString first(1,input.next());
    if (first.empty()) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null
    if ( first[0] != '^' ) {
      input.reset();
      return NarrowString();
    }

    return NarrowString(1,input.next());
  }
} // esapi
