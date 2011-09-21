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
#include "codecs/Codec.h"

  /**
  * Implementation of the Codec interface for HTML entity encoding.
  *
  * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
  *         href="http://www.aspectsecurity.com">Aspect Security</a>
  * @author Dan Amodio (dan.amodio@aspectsecurity.com)
  * @since June 1, 2007
  * @see org.owasp.esapi.Encoder
  */
namespace esapi {
  class ESAPI_EXPORT HTMLEntityCodec : public Codec {

    typedef std::map<int, String> EntityMap;
    typedef std::map<int, String>::const_iterator EntityMapIterator;

  private:
    static Char REPLACEMENT_CHAR();
    static const String& REPLACEMENT_HEX();
    static const String& REPLACEMENT_STR();

    /**
    * getNumericEntry checks input to see if it is a numeric entity
    *
    * @param input
    * 			The input to test for being a numeric entity
    *
    * @return
    * 			null if input is null, the character of input after decoding
    */
    Char getNumericEntity( PushbackString& );

    /**
    * Parse a decimal number, such as those from JavaScript's String.fromCharCode(value)
    *
    * @param input
    * 			decimal encoded string, such as 65
    * @return
    * 			character representation of this decimal value, e.g. A
    * @throws NumberFormatException
    */
    Char parseNumber( PushbackString& );

    /**
    * Parse a hex encoded entity
    *
    * @param input
    * 			Hex encoded input (such as 437ae;)
    * @return
    * 			A single character from the string
    * @throws NumberFormatException
    */
    Char parseHex( PushbackString& );

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
    Char getNamedEntity( PushbackString& str );

    /**
    * Retrieve the class wide intialization lock.
    * @return the mutex used to lock the class.
    */
    static Mutex& getClassMutex();

    /**
    * Build a unmodifiable Map from entity Character to Name.
    * @return Unmodifiable map.
    */
    static const EntityMap& getCharacterToEntityMap();

  public:
    /**
    * Default constructor
    */
    HTMLEntityCodec() {};

   /**
    * Standard destructor
    */
    virtual ~HTMLEntityCodec() {};

    /**
    * {@inheritDoc}
    *
    * Encodes a Character for safe use in an HTML entity field.
    * @param immune
    */
    String encodeCharacter( const Char* immune, size_t length, Char ch ) const;

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
    Char decodeCharacter( PushbackString& str ) const;
  };
}; // esapi namespace

