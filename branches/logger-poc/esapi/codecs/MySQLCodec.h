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

#include <string>

#include "codecs/PushbackString.h"
#include "codecs/Codec.h"

/**
 * Implementation of the Codec interface for MySQL strings. See http://mirror.yandex.ru/mirrors/ftp.mysql.com/doc/refman/5.0/en/string-syntax.html
 * for more information.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
namespace esapi {
  class ESAPI_EXPORT MySQLCodec : public Codec {

  public:
    /**
     * Specifies the SQL Mode the target MySQL Server is running with. For details about MySQL Server Modes
     * please see the Manual at {@link http://dev.mysql.com/doc/refman/5.0/en/server-sql-mode.html#sqlmode_ansi}
     *
     * Currently the only supported modes are:
     * ANSI
     * STANDARD
     */
    enum Mode { ANSI_MODE = 1, MYSQL_MODE = 0 };

  private:
    enum Mode mode;

    /**
     * encodeCharacterANSI encodes for ANSI SQL.
     *
     * Apostrophe is encoded
     *
     * Bug ###: In ANSI Mode Strings can also be passed in using the quotation. In ANSI_QUOTES mode a quotation
     * is considered to be an identifier, thus cannot be used at all in a value and will be dropped completely.
     *
     * @param c
     * 			character to encode
     * @return
     * 			String encoded to standards of MySQL running in ANSI mode
     */
    NarrowString encodeCharacterANSI( const NarrowString& ch ) const;

    /**
     * Encode a character suitable for MySQL
     *
     * @param c
     * 			Character to encode
     * @return
     * 			Encoded Character
     */
    NarrowString encodeCharacterMySQL( const NarrowString& ch ) const;

    /**
     * decodeCharacterANSI decodes the next character from ANSI SQL escaping
     *
     * @param input
     * 			A PushBackString containing characters you'd like decoded
     * @return
     * 			A single character, decoded
     */
    NarrowString decodeCharacterANSI( PushbackString& ) const;

    /**
     * decodeCharacterMySQL decodes all the potential escaped characters that MySQL is prepared to escape
     *
     * @param input
     * 			A string you'd like to be decoded
     * @return
     * 			A single character from that string, decoded.
     */
    NarrowString decodeCharacterMySQL( PushbackString& ) const;

  public:
    /** Target MySQL Server is running in Standard MySQL (Default) mode. */
    //static const int MYSQL_MODE = 0;
    /** Target MySQL Server is running in {@link http://dev.mysql.com/doc/refman/5.0/en/ansi-mode.html ANSI Mode} */
    //static const int ANSI_MODE = 1;

    /**
     * Instantiate the MySQL Codec with the given SQL {@link Mode}.
     * @param mode The mode the target server is running in
     */
    MySQLCodec( Mode mode ) { this->mode = mode; }

    /**
     * {@inheritDoc}
     *
     * Returns quote-encoded character
     *
     * @param immune
     */
    NarrowString encodeCharacter(const StringArray& immune, const NarrowString& ch) const;


    /**
     * {@inheritDoc}
     *
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     *
     * Formats all are legal (case sensitive)
     *   In ANSI_MODE '' decodes to '
     *   In MYSQL_MODE \x decodes to x (or a small list of specials)
     */
    NarrowString decodeCharacter( PushbackString& ) const;

  };
}; // esapi namespace
