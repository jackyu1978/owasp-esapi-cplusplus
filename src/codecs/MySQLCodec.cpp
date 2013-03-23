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
  NarrowString MySQLCodec::encodeCharacter(const StringArray& immune, const NarrowString& ch) const
  {
    ASSERT(!immune.empty());
    ASSERT(!ch.empty());

    if(ch.empty())
      return NarrowString();

    // check for immune characters
    for (size_t i=0; i<immune.size(); ++i) {
      if (immune[i] == ch)
        return ch;
    }

    // check for alphanumeric characters
    String hex = Codec::getHexForNonAlphanumeric( ch );
    if ( hex.empty() ) {
      return ch;
    }

    switch( mode ) {
    case ANSI_MODE: return encodeCharacterANSI( ch );
    case MYSQL_MODE: return encodeCharacterMySQL( ch );
    default: ASSERT(0);
    }

    return NarrowString();
  }

  NarrowString MySQLCodec::decodeCharacter( PushbackString& input) const {
    switch( mode ) {
    case ANSI_MODE: return decodeCharacterANSI( input );
    case MYSQL_MODE: return decodeCharacterMySQL( input );
    default: ASSERT(0);
    }
    return NarrowString();
  }

  NarrowString MySQLCodec::encodeCharacterANSI(const NarrowString& ch) const {
    if ( ch[0] == '\'' )
      return String("\'\'");
    if ( ch[0] == '\"' )
      return NarrowString();
    return ch;
  }

  NarrowString MySQLCodec::encodeCharacterMySQL(const NarrowString& ch) const
  {
    ASSERT(ch.length() == 1);

    if ( ch[0] == 0x00 ) return String("\\0");
    if ( ch[0] == 0x08 ) return String("\\b");
    if ( ch[0] == 0x09 ) return String("\\t");
    if ( ch[0] == 0x0a ) return String("\\n");
    if ( ch[0] == 0x0d ) return String("\\r");
    if ( ch[0] == 0x1a ) return String("\\Z");
    if ( ch[0] == 0x22 ) return String("\\\"");
    if ( ch[0] == 0x25 ) return String("\\%");
    if ( ch[0] == 0x27 ) return String("\\'");
    if ( ch[0] == 0x5c ) return String("\\\\");
    if ( ch[0] == 0x5f ) return String("\\_");

    return String("\\") + ch;
  }

  NarrowString MySQLCodec::decodeCharacterANSI( PushbackString& input) const {
    input.mark();
    NarrowString first(1, input.next());
    if ( first.empty() ) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null
    if ( first[0] != '\'' ) {
      input.reset();
      return NarrowString();
    }

    NarrowString second(1, input.next());
    if ( second.empty() ) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null
    if ( second[0] != '\'' ) {
      input.reset();
      return NarrowString();
    }
    return NarrowString(1,'\'');
  }

  NarrowString MySQLCodec::decodeCharacterMySQL( PushbackString& input) const {
    input.mark();
    NarrowString first(1,input.next());
    if ( first.empty() ) {
      input.reset();
      return NarrowString();
    }

    // if this is not an encoded character, return null
    if ( first[0] != '\\' ) {
      input.reset();
      return NarrowString();
    }

    NarrowString second(1, input.next());
    if ( second.empty() ) {
      input.reset();
      return NarrowString();
    }

    if ( second == "0" ) {
      return NarrowString("\x00");
    } else if ( second == "b" ) {
      return NarrowString("\x08");
    } else if ( second == "t" ) {
      return NarrowString("\x09");
    } else if ( second == "n" ) {
      return NarrowString("\x0a");
    } else if ( second == "r" ) {
      return NarrowString("\x0d");
    } else if ( second == "z" ) {
      return NarrowString("\x1a");
    } else if ( second == "\"" ) {
      return NarrowString("\x22");
    } else if ( second == "%" ) {
      return NarrowString("\x25");
    } else if ( second == "\'" ) {
      return NarrowString("\x27");
    } else if ( second == "\\" ) {
      return NarrowString("\x5c");
    } else if ( second == "_" ) {
      return NarrowString("\x5f");
    } else {
      return second;
    }
  }
} // esapi
