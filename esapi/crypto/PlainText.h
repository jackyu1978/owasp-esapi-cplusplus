/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#pragma once

#include "EsapiCommon.h"

ESAPI_MS_WARNING_PUSH(3)
#include <cryptopp/secblock.h>
ESAPI_MS_WARNING_POP()

ESAPI_MS_NO_WARNING(4251)

namespace esapi
{

  typedef std::string PlainText;

}; // NAMESPACE esapi
