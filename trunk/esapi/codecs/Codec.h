/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* The ESAPI is published by OWASP under the BSD license. You should read and accept the
* LICENSE before you use, modify, and/or redistribute this software.
*
* @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
* @created 2011
*/

#pragma once

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "codecs/PushbackString.h"
#include "crypto/CryptoppCommon.h"

/**
* The Codec interface defines a set of methods for encoding and decoding application level encoding schemes,
* such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding
* and canonicalization. The design of these codecs allows for character-by-character decoding, which is
* necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques
* used by attackers to bypass validation and bury encoded attacks in data.
*
* @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
* href="http://www.aspectsecurity.com">Aspect Security</a>
* @author Dan Amodio (dan.amodio@aspectsecurity.com)
* @since June 1, 2007
* @see org.owasp.esapi.Encoder
*/

namespace esapi {

  class ESAPI_EXPORT Codec {

  private:

    /**
    * Used to initialize the values of private member hex
    *
    * @return reference to the initialized array
    */
    ESAPI_PRIVATE static const StringArray& getHexArray ();

    /**
    * Retrieve the class wide intialization lock.
    *
    * @return the mutex used to lock the class.
    */
    ESAPI_PRIVATE static Mutex& getClassMutex ();


    /**
    * Encode a String so that it can be safely used in a specific context.
    *
    * @param immune
    * an array of charaters which should not be encoded. Each character
    * should be encoded as a UTF-8 string due to surrogates which could
    * overflow a 8-bit ot 16-bit character.
    * @param str
    * the String to encode
    * @return
    * the encoded String
    */
    virtual NarrowString encode(const StringArray& immune, const NarrowString& str) const;

    /**
    * Default implementation that should be overridden in specific codecs.
    *
    * @param immune
    * an array of charaters which should not be encoded. Each character
    * should be encoded as a UTF-8 string due to surrogates which could
    * overflow a 8-bit ot 16-bit character.
    * @param ch
    * the Character to encode. The character is stored in a string due
    * to surrogates which could overflow a 8-bit ot 16-bit character.
    * @return
    * the encoded Character stored in a string
    */
    virtual NarrowString encodeCharacter(const StringArray& immune, const String& ch) const;

    /**
    * Decode a String that was encoded using the encode method in this Class
    *
    * @param input
    * the String to decode
    * @return
    * the decoded String
    */
    virtual NarrowString decode(const NarrowString&) const;

    /**
    * Returns the decoded version of the next character from the input string and advances the
    * current character in the PushbackString. If the current character is not encoded, this
    * method MUST reset the PushbackString.
    *
    * @param input the Character to decode
    *
    * @return the decoded Character
    */
    virtual NarrowString decodeCharacter(PushbackString&) const;

    /**
    * Lookup the hexadecimal value of any character that is not alphanumeric.
    *
    * @param c The character to lookup.
    * @return
    * return null if alphanumeric or the character code in hex.
    */
    static NarrowString getHexForNonAlphanumeric(const NarrowString& ch);

    /**
    * Lookup the octal value of any character that is not alphanumeric.
    *
    * @param ch The character to lookup.
    * @return
    * return null if alphanumeric or the character code in hex.
    */
    static NarrowString toOctal(const NarrowString& ch);

    /**
    * Lookup the decimal value of any character that is not alphanumeric.
    *
    * @param ch The character to lookup.
    * @return
    * return null if alphanumeric or the character code in hex.
    */
    static NarrowString toDec(const NarrowString& ch);

    /**
    * Lookup the hexadecimal value of any character that is not alphanumeric.
    *
    * @param ch The character to lookup.
    * @return
    * return null if alphanumeric or the character code in hex.
    */
    static NarrowString toHex(const NarrowString& ch);

    /**
    * Utility to search a character array for a specific Char.
    *
    * @param ch character to search for in array
    * @param str array of characters
    * @return true if character c is found, false otherwise
    */
    bool containsCharacter(const NarrowString& ch, const NarrowString& str) const;

  protected:
    /**
    * Default constructor
    */
    Codec() {};

    /**
    *
    */
    static NarrowString toBase(const NarrowString& ch, unsigned int base);

  public:
    /**
    * Standard destructor
    */
    virtual ~Codec() {};

  };

}; /** esapi Namespace */
