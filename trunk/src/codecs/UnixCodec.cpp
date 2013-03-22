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
#include "codecs/UnixCodec.h"
#include "codecs/Codec.h"
#include "EsapiCommon.h"

namespace esapi
{
  NarrowString UnixCodec::encodeCharacter( const Char immune[], size_t length, Char c) const {
	  ASSERT (c != 0);

	  // check for immune characters
	  for (unsigned int i=0; i<length; i++) {
		  if (immune[i] == c)
			  return String(1,c);
	  }

	  // check for alphanumeric characters
	  NarrowString hex = Codec::getHexForNonAlphanumeric( c );
	  if ( hex.empty() ) {
		  return NarrowString(1,c);
	  }

    return NarrowString("\\")+c;
  }

  NarrowString UnixCodec::decodeCharacter(PushbackString& input) const {
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
