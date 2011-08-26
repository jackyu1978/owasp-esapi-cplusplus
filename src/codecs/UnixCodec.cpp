/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#include <string>

#include "codecs/UnixCodec.h"
#include "codecs/Codec.h"
#include "EsapiCommon.h"

std::string esapi::UnixCodec::encodeCharacter( const char immune[], size_t length, char c) const {
	ASSERT (c != 0);

	// check for immune characters
	for (unsigned int i=0; i<length; i++) {
		if (immune[i] == c)
			return (std::string)""+c;
	}

	// check for alphanumeric characters
	std::string hex = esapi::Codec::getHexForNonAlphanumeric( c );
	if ( hex.compare("") == 0 ) {
		return (std::string)""+c;
	}

    return (std::string)"\\"+c;
}

char esapi::UnixCodec::decodeCharacter( PushbackString& input) const {
	input.mark();
	char first = input.next();
	if ( first == 0 ) {
		input.reset();
		return '\0';
	}

	// if this is not an encoded character, return null
	if ( first != '\\' ) {
		input.reset();
		return '\0';
	}

	char second = input.next();
	return second;
}
