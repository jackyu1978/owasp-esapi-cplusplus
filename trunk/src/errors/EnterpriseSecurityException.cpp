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

#include "EsapiCommon.h"
#include "util/TextConvert.h"
#include "errors/EnterpriseSecurityException.h"

namespace esapi
{
  EnterpriseSecurityException::EnterpriseSecurityException(const String &userMessage, const String &newLogMessage )
        : userMessage(TextConvert::WideToNarrow(userMessage)), logMessage(TextConvert::WideToNarrow(newLogMessage))
  {
	  /**
      if (!ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
    	  ESAPI.intrusionDetector().addException(this);
      }*/
  }

  EnterpriseSecurityException::EnterpriseSecurityException(const NarrowString& userMessage, const NarrowString& logMessage)
    : userMessage(userMessage), logMessage(logMessage)
  {    
  }

  String EnterpriseSecurityException::getUserMessage() const
  {
    ASSERT( !userMessage.empty() );
    return TextConvert::NarrowToWide(userMessage);
  }

  const char* EnterpriseSecurityException::what() const throw()
  {
    ASSERT( !userMessage.empty() );
    return userMessage.c_str();
  }

  String EnterpriseSecurityException::getLogMessage() const
  {
    ASSERT( !logMessage.empty() );
	  return TextConvert::NarrowToWide(logMessage);
  }
} // esapi

