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

#ifndef _PushbackString_H_
#define _PushbackString_H_

#include <string>

namespace esapi {
/**
 * The pushback string is used by Codecs to allow them to push decoded characters back onto a string
 * for further decoding. This is necessary to detect double-encoding.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
class PushbackString {

private:
	std::string input;
	char varPushback;
	char temp;
	unsigned int varIndex;
	unsigned int varMark;

public:
    /**
     *
     * @param input
     */
    PushbackString( std::string);

    /**
     *
     * @param c
     */
    void pushback( char );

	/*
	 * Get the current index of the PushbackString. Typically used in error messages.
	 *
     * @return int
     */
    int index();

    /**
     *
     * @return bool
     */
    bool hasNext();

    /**
     *
     * @return char
     */
    char next();

    /**
    *
    * @return char
    */
   char nextHex();

   /**
   *
   * @return char
   */
  char nextOctal();

  /**
   * Returns true if the parameter character is a hexidecimal digit 0 through 9, a through f, or A through F.
   * @param c
   * @return
   */
  static bool isHexDigit( char );

 /**
 * Returns true if the parameter character is an octal digit 0 through 7.
 * @param c
 * @return
 */
 static bool isOctalDigit( char );

    /**
     * Return the next character without affecting the current index.
     * @return
     */
    char peek();

    /**
     * Test to see if the next character is a particular value without affecting the current index.
     * @param c
     * @return
     */
    bool peek( char );

    /**
     *
     */
    void mark();

    /**
     *
     */
    void reset();

protected:
    /**
     *
     * @return
     */
    std::string remainder();

};

}; /* esapi namespace */

#endif /* _PushbackString_H_ */
