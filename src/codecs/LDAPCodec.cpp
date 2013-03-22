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
      case L'\\':
              return "\\5c";
              break;
      case L'*':
              return "\\2a";
              break;
      case L'(':
              return "\\28";
              break;
      case L')':
			  return "\\29";
              break;
      case L'\0':
              return "\\00";
              break;
      default:
              return String(1, c);
      }
  }

  Char LDAPCodec::decodeCharacter(PushbackString& input) const {
    ASSERT(input.hasNext());

	  input.mark();
	  Char first = input.next();
	  if ( first == 0 ) {
		  input.reset();
		  return L'\0';
	  }

	  // if this is not an encoded character, return null
	  if ( first != L'\\' ) {
		  input.reset();
		  return L'\0';
	  }

	  Char second = input.next();
	  return second;
  }
} // esapi
