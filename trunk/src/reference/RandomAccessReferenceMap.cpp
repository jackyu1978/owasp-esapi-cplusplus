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
 * @author Dan Amodio (dan.amodio@aspectsecurity.com)
 *
 * @created 2007
 */

#include "EsapiCommon.h"
#include "reference/RandomAccessReferenceMap.h"

namespace esapi
{
  String RandomAccessReferenceMap::getUniqueReference()
  {
	  String candidate;
    do
    {      
      //  candidate = ESAPI.randomizer().getRandomString(6, EncoderConstants.CHAR_ALPHANUMERICS);
    }
    while (/*itod.keySet().contains(candidate)*/ false );

    return candidate;
  }
} // esapi