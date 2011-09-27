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

  class ESAPI_EXPORT ExecutionException : public EnterpriseSecurityException
  {
  public:
    explicit ExecutionException(const String &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit ExecutionException(const String &userMessage, const String &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }

    explicit ExecutionException(const NarrowString &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit ExecutionException(const NarrowString &userMessage, const NarrowString &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }
  };

} // NAMESPACE
