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

#ifndef _Codec_H_
#define _Codec_H_

#include <string>
#include "codecs/PushbackString.h"

namespace esapi {
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
class Codec {

private:

	/*template <>
	std::string* initHexArray(){
		std::string foo[256] = {"bar", "bar", "bar"};
		return foo;
	}*/

	/**
	 * Initialize an array to mark which characters are to be encoded. Store the hex
	 * string for that character to save time later. If the character shouldn't be
	 * encoded, then store null.
	 */
	const static std::string * hex;

	/**
	 * Used to initialize the values of private member hex
	 *
	 * @return pointer to the initialized array
	 */
	static std::string* hexArray ();


public:
	/**
	 * Default constructor
	 */
	Codec() {};

	/**
	 * Encode a String so that it can be safely used in a specific context.
	 *
	 * @param immune
	 * @param input
	 * 		the String to encode
	 * @return the encoded String
	 */
	virtual std::string encode(char[], std::string);

	/**
	 * Default implementation that should be overridden in specific codecs.
	 *
	 * @param immune
	 * @param c
	 * 		the Character to encode
	 * @return
	 * 		the encoded Character
	 */
	virtual std::string encodeCharacter( char[], char);

	/**
	 * Decode a String that was encoded using the encode method in this Class
	 *
	 * @param input
	 * 		the String to decode
	 * @return
	 *		the decoded String
	 */
	virtual std::string decode(std::string);

	/**
	 * Returns the decoded version of the next character from the input string and advances the
	 * current character in the PushbackString.  If the current character is not encoded, this
	 * method MUST reset the PushbackString.
	 *
	 * @param input	the Character to decode
	 *
	 * @return the decoded Character
	 */
	virtual char decodeCharacter( PushbackString);

	/**
	 * Lookup the hex value of any character that is not alphanumeric.
	 * @param c The character to lookup.
	 * @return, return null if alphanumeric or the character code
	 * 	in hex.
	 */
	std::string getHexForNonAlphanumeric(char);

	std::string toOctal(char);

	std::string toHex(char);

	/**
	 * Utility to search a char[] for a specific char.
	 *
	 * @param c
	 * @param array
	 * @return
	 */
	bool containsCharacter( char, char[]);

};

}; /* esapi Namespace */

#endif /* _Codec_H_ */
