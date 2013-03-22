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
		return String("\'\'");

	if (c == ';')
		return String(".");

    return String("")+c;
  }

  Char DB2Codec::decodeCharacter( PushbackString& input) const {
		input.mark();
		Char first = input.next();

		if (first == 0) {
			input.reset();
			return '\0';
		}

		// if this is not an encoded character, return null

		if (first != '\'') {
			input.reset();
			return '\0';
		}

		Char second = input.next();

		if (second == '0') {
			input.reset();
			return '\0';
		}

		// if this is not an encoded character, return null
		if (second != '\'') {
			input.reset();
			return '\0';
		}

		return '\'';
  }
} // esapi
