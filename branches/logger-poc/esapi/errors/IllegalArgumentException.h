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

  class ESAPI_EXPORT IllegalArgumentException : public EnterpriseSecurityException
  {
  public:
    explicit IllegalArgumentException(const WideString &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit IllegalArgumentException(const WideString &userMessage, const WideString &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }

    explicit IllegalArgumentException(const NarrowString &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit IllegalArgumentException(const NarrowString &userMessage, const NarrowString &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }
  };

} // NAMESPACE

