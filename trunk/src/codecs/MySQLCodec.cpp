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
#include "codecs/MySQLCodec.h"
#include "codecs/Codec.h"
#include "EsapiCommon.h"

namespace esapi
{
  NarrowString MySQLCodec::encodeCharacter( const Char immune[], size_t length, Char c) const {
	  ASSERT (c != 0);

	  // check for immune characters
	  for (unsigned int i=0; i<length; i++) {
		  if (immune[i] == c)
			  return String(1,c);
	  }

	  // check for alphanumeric characters
	  String hex = Codec::getHexForNonAlphanumeric( c );
	  if ( hex.empty() ) {
		  return String(1,c);
	  }

	switch( mode ) {
		case ANSI_MODE: return encodeCharacterANSI( c );
		case MYSQL_MODE: return encodeCharacterMySQL( c );
	}

	return String("\0");
  }

  Char MySQLCodec::decodeCharacter( PushbackString& input) const {
		switch( mode ) {
			case ANSI_MODE: return decodeCharacterANSI( input );
			case MYSQL_MODE: return decodeCharacterMySQL( input );
		}
	  return '\0';
  }

  NarrowString MySQLCodec::encodeCharacterANSI( Char c ) const {
		if ( c == '\'' )
      	return String("\'\'");
      if ( c == '\"' )
          return String("");
      return String("")+c;
  }

  String MySQLCodec::encodeCharacterMySQL( Char c ) const {
		if ( c == 0x00 ) return String("\\0");
		if ( c == 0x08 ) return String("\\b");
		if ( c == 0x09 ) return String("\\t");
		if ( c == 0x0a ) return String("\\n");
		if ( c == 0x0d ) return String("\\r");
		if ( c == 0x1a ) return String("\\Z");
		if ( c == 0x22 ) return String("\\\"");
		if ( c == 0x25 ) return String("\\%");
		if ( c == 0x27 ) return String("\\'");
		if ( c == 0x5c ) return String("\\\\");
		if ( c == 0x5f ) return String("\\_");
	    return String("\\") + c;
  }

  Char MySQLCodec::decodeCharacterANSI( PushbackString& input) const {
		input.mark();
		Char first = input.next();
		if ( first == 0 ) {
			input.reset();
			return '\0';
		}

		// if this is not an encoded character, return null
		if ( first != '\'' ) {
			input.reset();
			return '\0';
		}

		Char second = input.next();
		if ( second == 0 ) {
			input.reset();
			return '\0';
		}

		// if this is not an encoded character, return null
		if ( second != '\'' ) {
			input.reset();
			return '\0';
		}
		return '\'';
  }

  Char MySQLCodec::decodeCharacterMySQL( PushbackString& input) const {
		input.mark();
		Char first = input.next();
		if ( first == 0 ) {
			input.reset();
			return '\0';
		}

		// if this is not an encoded character, return null
		if ( first != '\\' ) {
			input.reset();
			return '\0';
		}

		Char second = input.next();
		if ( second == 0 ) {
			input.reset();
			return '\0';
		}

		if ( second == '0' ) {
			return (Char)0x00;
		} else if ( second == 'b' ) {
			return (Char)0x08;
		} else if ( second == 't' ) {
			return (Char)0x09;
		} else if ( second == 'n' ) {
			return (Char)0x0a;
		} else if ( second == 'r' ) {
			return (Char)0x0d;
		} else if ( second == 'z' ) {
			return (Char)0x1a;
		} else if ( second == '\"' ) {
			return (Char)0x22;
		} else if ( second == '%' ) {
			return (Char)0x25;
		} else if ( second == '\'' ) {
			return (Char)0x27;
		} else if ( second == '\\' ) {
			return (Char)0x5c;
		} else if ( second == '_' ) {
			return (Char)0x5f;
		} else {
			return second;
		}
  }


} // esapi
