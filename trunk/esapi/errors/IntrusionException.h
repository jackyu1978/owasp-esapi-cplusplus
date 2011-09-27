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
namespace esapi
{
  class ESAPI_EXPORT IntrusionException : public EnterpriseSecurityException
  {
  public:
    explicit IntrusionException(const String &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit IntrusionException(const String &userMessage, const String &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }

    explicit IntrusionException(const NarrowString &message)
      : EnterpriseSecurityException(message, message)
      {
      }
    explicit IntrusionException(const NarrowString &userMessage, const NarrowString &logMessage)
      : EnterpriseSecurityException(userMessage, logMessage)
      {
      }
  };
} // NAMESPACE
