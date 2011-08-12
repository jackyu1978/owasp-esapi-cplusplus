/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#pragma once

#include "EsapiCommon.h"

#include <set>

namespace esapi {
/**
 * Common character classes used for input validation, output encoding, verifying password strength
 * CSRF token generation, generating salts, etc
 * @author Neil Matatall (neil.matatall .at. gmail.com)
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @see User
 */
class EncoderConstants {

public:

	/**
	 * !$*-.=?@_
	 */
	static const char CHAR_PASSWORD_SPECIALS [];
	static const std::set<char> PASSWORD_SPECIALS;


	/**
	 * a-b
	 */
	static const char CHAR_LOWERS[];
	static const std::set<char> LOWERS;

	/**
	 * A-Z
	 */
	static const char CHAR_UPPERS[];
	static const std::set<char> UPPERS;

	/**
	 * 0-9
	 */
	static const char CHAR_DIGITS[];
	static const std::set<char> DIGITS;

	/**
	 * !$*+-.=?@^_|~
	 */
	static const char CHAR_SPECIALS[];
	static const std::set<char> SPECIALS;

	/**
	 * CHAR_LOWERS union CHAR_UPPERS
	 */
	static const char CHAR_LETTERS[];
	static const std::set<char> LETTERS;

	/**
	 * CHAR_LETTERS union CHAR_DIGITS
	 */
	static const char CHAR_ALPHANUMERICS[];
	static const std::set<char> ALPHANUMERICS;

	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 */
	static const char CHAR_PASSWORD_LOWERS[];
	static const std::set<char> PASSWORD_LOWERS;

	/**
	 *
	 */
	static const char CHAR_PASSWORD_UPPERS[];
	static const std::set<char> PASSWORD_UPPERS;

	/**
	 * 2-9
	 */
	static const char CHAR_PASSWORD_DIGITS[];
	static const std::set<char> PASSWORD_DIGITS;

	/**
	 * CHAR_PASSWORD_LOWERS union CHAR_PASSWORD_UPPERS
	 */
	static const char CHAR_PASSWORD_LETTERS[];
	static const std::set<char> PASSWORD_LETTERS;

private:
	EncoderConstants() {
		// prevent instantiation
	}

};

}; /** esapi namespace */
