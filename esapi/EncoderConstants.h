
#ifndef _EncoderConstants_h_
#define _EncoderConstants_h_

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
	public final static char[] CHAR_ALPHANUMERICS = StringUtilities.union(CHAR_LETTERS, CHAR_DIGITS);
	public final static Set<Character> ALPHANUMERICS;
	static {
		ALPHANUMERICS = CollectionsUtil.arrayToSet(CHAR_ALPHANUMERICS);
	}

	/**
	 * Password character set, is alphanumerics (without l, i, I, o, O, and 0)
	 * selected specials like + (bad for URL encoding, | is like i and 1,
	 * etc...)
	 */
	public final static char[] CHAR_PASSWORD_LOWERS = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
	public final static Set<Character> PASSWORD_LOWERS;
	static {
		PASSWORD_LOWERS = CollectionsUtil.arrayToSet(CHAR_ALPHANUMERICS);
	}

	/**
	 *
	 */
	public final static char[] CHAR_PASSWORD_UPPERS = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
	public final static Set<Character> PASSWORD_UPPERS;
	static {
		PASSWORD_UPPERS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_UPPERS);
	}

	/**
	 * 2-9
	 */
	public final static char[] CHAR_PASSWORD_DIGITS = { '2', '3', '4', '5', '6', '7', '8', '9' };
	public final static Set<Character> PASSWORD_DIGITS;
	static {
		PASSWORD_DIGITS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_DIGITS);
	}

	/**
	 * CHAR_PASSWORD_LOWERS union CHAR_PASSWORD_UPPERS
	 */
	public final static char[] CHAR_PASSWORD_LETTERS = StringUtilities.union( CHAR_PASSWORD_LOWERS, CHAR_PASSWORD_UPPERS );
	public final static Set<Character> PASSWORD_LETTERS;
	static {
		PASSWORD_LETTERS = CollectionsUtil.arrayToSet(CHAR_PASSWORD_LETTERS);
	}

	private EncoderConstants() {
		// prevent instantiation
	}

};

}; /* esapi namespace */

#endif /* _EncoderConstants_h_ */
