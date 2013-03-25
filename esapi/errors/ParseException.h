/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2013 - The OWASP Foundation
 */

#pragma once

#include "EsapiCommon.h"
#include "errors/EnterpriseSecurityException.h"

#include <stdexcept>
#include <string>

// TODO: Finish Porting from Java

namespace esapi {

  class ESAPI_EXPORT ParseException : public EnterpriseSecurityException
  {
  public:
    explicit ParseException(const WideString &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit ParseException(const WideString &userMessage, const WideString &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }

    explicit ParseException(const NarrowString &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit ParseException(const NarrowString &userMessage, const NarrowString &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }
  };

} // NAMESPACE

