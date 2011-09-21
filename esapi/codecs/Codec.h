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

#include <vector>

  /**
   * The Codec interface defines a set of methods for encoding and decoding application level encoding schemes,
   * such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding
   * and canonicalization.  The design of these codecs allows for character-by-character decoding, which is
   * necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques
   * used by attackers to bypass validation and bury encoded attacks in data.
   *
   * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
   *         href="http://www.aspectsecurity.com">Aspect Security</a>
   * @author Dan Amodio (dan.amodio@aspectsecurity.com)
   * @since June 1, 2007
   * @see org.owasp.esapi.Encoder
   */

namespace esapi {

  class ESAPI_EXPORT Codec {

  private:

    /**template <>
      String* initHexArray(){
      String foo[256] = {"bar", "bar", "bar"};
      return foo;
      }*/

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

  public:
    /**
     * Default constructor
     */
    Codec() {};

    /**
     * Standard destructor
     */
    virtual ~Codec() {};

    /**
     * Encode a String so that it can be safely used in a specific context.
     *
     * @param immune
     * @param input
     * 		the String to encode
     * @return the encoded String
     */
    virtual String encode(const Char immune[], size_t length, const String&) const;

    /**
     * Default implementation that should be overridden in specific codecs.
     *
     * @param immune
     * @param c
     * 		the Character to encode
     * @return
     * 		the encoded Character
     */
    virtual String encodeCharacter(const Char immune[], size_t length, Char c) const;

    /**
     * Decode a String that was encoded using the encode method in this Class
     *
     * @param input
     * 		the String to decode
     * @return
     *		the decoded String
     */
    virtual String decode(const String&) const;

    /**
     * Returns the decoded version of the next character from the input string and advances the
     * current character in the PushbackString.  If the current character is not encoded, this
     * method MUST reset the PushbackString.
     *
     * @param input	the Character to decode
     *
     * @return the decoded Character
     */
    virtual Char decodeCharacter(PushbackString&) const;

    /**
     * Lookup the hex value of any character that is not alphanumeric.
     * @param c The character to lookup.
     * @return, return null if alphanumeric or the character code
     * 	in hex.
     */
    static String getHexForNonAlphanumeric(Char);

    static String toOctal(Char);

    static String toHex(Char);

    /**
     * Utility to search a string for a specific Char.
     *
     * @param c
     * @param s
     * @return true if character c is found, false otherwise
     */
    bool containsCharacter(Char a, const String& s) const;

    /**
     * Utility to search a character array for a specific Char.
     *
     * @param c character to search for in array
     * @param array array of characters
     * @param length length of array
     * @return true if character c is found, false otherwise
     */
    bool containsCharacter(Char c, const Char array[], size_t length) const;

  };

}; /** esapi Namespace */

