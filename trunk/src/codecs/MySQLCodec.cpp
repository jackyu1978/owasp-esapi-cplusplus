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
  String MySQLCodec::encodeCharacter( const Char immune[], size_t length, Char c) const {
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

	return String(L"\0");
  }

  Char MySQLCodec::decodeCharacter( PushbackString& input) const {
		switch( mode ) {
			case ANSI_MODE: return decodeCharacterANSI( input );
			case MYSQL_MODE: return decodeCharacterMySQL( input );
		}
	  return L'\0';
  }

  String MySQLCodec::encodeCharacterANSI( Char c ) const {
		if ( c == L'\'' )
      	return String(L"\'\'");
      if ( c == L'\"' )
          return String(L"");
      return String(L"")+c;
  }

  String MySQLCodec::encodeCharacterMySQL( Char c ) const {
		if ( c == 0x00 ) return String(L"\\0");
		if ( c == 0x08 ) return String(L"\\b");
		if ( c == 0x09 ) return String(L"\\t");
		if ( c == 0x0a ) return String(L"\\n");
		if ( c == 0x0d ) return String(L"\\r");
		if ( c == 0x1a ) return String(L"\\Z");
		if ( c == 0x22 ) return String(L"\\\"");
		if ( c == 0x25 ) return String(L"\\%");
		if ( c == 0x27 ) return String(L"\\'");
		if ( c == 0x5c ) return String(L"\\\\");
		if ( c == 0x5f ) return String(L"\\_");
	    return String(L"\\") + c;
  }

  Char MySQLCodec::decodeCharacterANSI( PushbackString& input) const {
		input.mark();
		Char first = input.next();
		if ( first == 0 ) {
			input.reset();
			return L'\0';
		}

		// if this is not an encoded character, return null
		if ( first != L'\'' ) {
			input.reset();
			return L'\0';
		}

		Char second = input.next();
		if ( second == 0 ) {
			input.reset();
			return L'\0';
		}

		// if this is not an encoded character, return null
		if ( second != L'\'' ) {
			input.reset();
			return L'\0';
		}
		return L'\'';
  }

  Char MySQLCodec::decodeCharacterMySQL( PushbackString& input) const {
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
		if ( second == 0 ) {
			input.reset();
			return L'\0';
		}

		if ( second == L'0' ) {
			return (Char)0x00;
		} else if ( second == L'b' ) {
			return (Char)0x08;
		} else if ( second == L't' ) {
			return (Char)0x09;
		} else if ( second == L'n' ) {
			return (Char)0x0a;
		} else if ( second == L'r' ) {
			return (Char)0x0d;
		} else if ( second == L'z' ) {
			return (Char)0x1a;
		} else if ( second == L'\"' ) {
			return (Char)0x22;
		} else if ( second == L'%' ) {
			return (Char)0x25;
		} else if ( second == L'\'' ) {
			return (Char)0x27;
		} else if ( second == L'\\' ) {
			return (Char)0x5c;
		} else if ( second == L'_' ) {
			return (Char)0x5f;
		} else {
			return second;
		}
  }


} // esapi
