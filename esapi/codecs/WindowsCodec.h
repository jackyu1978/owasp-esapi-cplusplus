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

#include "codecs/PushbackString.h"
#include "codecs/Codec.h"

#include <string>

namespace esapi {
/**
 * Implementation of the Codec interface for '^' encoding from Windows command shell.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
class WindowsCodec : Codec {

public:
	/**
	 * {@inheritDoc}
	 *
	 * Returns Windows shell encoded character (which is ^)
     *
     * @param immune
     */
	std::string encodeCharacter( const char[], size_t, char) const;


	/**
	 * {@inheritDoc}
	 *
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * <p>
	 * Formats all are legal both upper/lower case:
	 *   ^x - all special characters
	 */
	char decodeCharacter( esapi::PushbackString& ) const;

};
}; // esapi namespace
