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
#include "errors/EnterpriseSecurityException.h"

#include <stdexcept>
#include <string>

// TODO: Finish Porting from Java

namespace esapi {

class ESAPI_EXPORT InvalidArgumentException : public EnterpriseSecurityException
{
public:
	explicit InvalidArgumentException(const std::string &message)
    : EnterpriseSecurityException(message, message)
  {
  }
  	explicit InvalidArgumentException(const std::string &userMessage, const std::string &logMessage)
    : EnterpriseSecurityException(userMessage, logMessage)
  {
  }
};

} // NAMESPACE