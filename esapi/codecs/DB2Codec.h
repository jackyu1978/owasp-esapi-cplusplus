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
 * Implementation of the Codec interface for DB2 strings. This function will only protect you from SQLi in limited situations.
 *
 * @author Sivasankar Tanakala (stanakal@TRS.NYC.NY.US)
 * @since October 26, 2010
 * @see esapi::Encoder
 */
namespace esapi {
  class ESAPI_EXPORT DB2Codec : public Codec {

  public:
    /**
     * {@inheritDoc}
     *
     *
     * @param immune
     */
    NarrowString encodeCharacter( const StringArray&, const NarrowString& ) const;


    /**
     * {@inheritDoc}
     *
     *
     */
    NarrowString decodeCharacter( PushbackString& ) const;

  };
}; // esapi namespace

