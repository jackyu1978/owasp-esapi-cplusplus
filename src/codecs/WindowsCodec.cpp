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
  String WindowsCodec::encodeCharacter( const Char immune[], size_t length, Char c) const {
	  ASSERT (c != 0);

	  // check for immune characters
	  for (size_t i=0; i<length; i++) {
		  if (immune[i] == c)
			  return String(1,c);
	  }

	  // check for alphanumeric characters
	  String hex = Codec::getHexForNonAlphanumeric( c );
	  if ( hex.compare("") == '\0' ) {
		  return String(1, c);
	  }

	  return (String)"^" + c;
  }

  Char WindowsCodec::decodeCharacter( PushbackString& input) const {
	  input.mark();
	  Char first = input.next();
	  if ( first == '\0' ) {
		  input.reset();
		  return '\0';
	  }

	  // if this is not an encoded character, return null
	  if ( first != '^' ) {
		  input.reset();
		  return '\0';
	  }

	  Char second = input.next();
	  return second;
  }
} // esapi
