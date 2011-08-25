/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2007 - The OWASP Foundation
*
* The ESAPI is published by OWASP under the BSD license. You should read and accept the
* LICENSE before you use, modify, and/or redistribute this software.
*
* @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
* @created 2007
*/

#pragma once

#include <string>
#include <map>

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "codecs/PushbackString.h"
#include "codecs/Trie.h"
#include "codecs/Codec.h"

namespace esapi {
  /**
  * Implementation of the Codec interface for HTML entity encoding.
  *
  * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
  *         href="http://www.aspectsecurity.com">Aspect Security</a>
  * @author Dan Amodio (dan.amodio@aspectsecurity.com)
  * @since June 1, 2007
  * @see org.owasp.esapi.Encoder
  */
  class ESAPI_EXPORT HTMLEntityCodec : public esapi::Codec {
  private:
    static const int REPLACEMENT_CHAR = 65533;
    static const std::string REPLACEMENT_HEX;
    static const std::string REPLACEMENT_STR;
    static Mutex s_mutex;
    static const std::map<int,std::string> characterToEntityMap;

    //TODO
    //static const Trie<Character> entityToCharacterTrie;

    /**
    * getNumericEntry checks input to see if it is a numeric entity
    *
    * @param input
    * 			The input to test for being a numeric entity
    *
    * @return
    * 			null if input is null, the character of input after decoding
    */
    char getNumericEntity( PushbackString );

    /**
    * Parse a decimal number, such as those from JavaScript's String.fromCharCode(value)
    *
    * @param input
    * 			decimal encoded string, such as 65
    * @return
    * 			character representation of this decimal value, e.g. A
    * @throws NumberFormatException
    */
    char parseNumber( PushbackString ) ;

    /**
    * Parse a hex encoded entity
    *
    * @param input
    * 			Hex encoded input (such as 437ae;)
    * @return
    * 			A single character from the string
    * @throws NumberFormatException
    */
    char parseHex( PushbackString ) ;

    /**
    *
    * Returns the decoded version of the character starting at index, or
    * null if no decoding is possible.
    *
    * Formats all are legal both with and without semi-colon, upper/lower case:
    *   &aa;
    *   &aaa;
    *   &aaaa;
    *   &aaaaa;
    *   &aaaaaa;
    *   &aaaaaaa;
    *
    * @param input
    * 		A string containing a named entity like &quot;
    * @return
    * 		Returns the decoded version of the character starting at index, or null if no decoding is possible.
    */
    char getNamedEntity( PushbackString ) ;

    /**
    * Build a unmodifiable Map from entity Character to Name.
    * @return Unmodifiable map.
    */
    static const std::map<int,std::string>& mkCharacterToEntityMap(); //TODO Thread safety?

    /**
    * Build a unmodifiable Trie from entitiy Name to Character
    * @return Unmodifiable trie.
    */
    //TODO static Trie<Character> mkEntityToCharacterTrie(); //TODO Thread safety?

  public:
    /**
    *
    */
    HTMLEntityCodec() {};

    /**
    * {@inheritDoc}
    *
    * Encodes a Character for safe use in an HTML entity field.
    * @param immune
    */
    std::string encodeCharacter( const char*, size_t, char ) const;

    /**
    * {@inheritDoc}
    *
    * Returns the decoded version of the character starting at index, or
    * null if no decoding is possible.
    *
    * Formats all are legal both with and without semi-colon, upper/lower case:
    *   &#dddd;
    *   &#xhhhh;
    *   &name;
    */
    char decodeCharacter( esapi::PushbackString& ) const;
  };
}; // esapi namespace
