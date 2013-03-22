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
 * Implementation of the Codec interface for encoding for LDAP
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
namespace esapi {
  class ESAPI_EXPORT LDAPCodec : public Codec {

  public:
    /**
     * {@inheritDoc}
     *
     * @param immune
     */
    NarrowString encodeCharacter( const Char[], size_t , Char ) const;


    /**
     * {@inheritDoc}
     *
     */
    NarrowString decodeCharacter( PushbackString& ) const;

  };
}; // esapi namespace

