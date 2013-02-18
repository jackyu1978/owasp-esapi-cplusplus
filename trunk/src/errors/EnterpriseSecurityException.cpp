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
  EnterpriseSecurityException::EnterpriseSecurityException(const NarrowString &userMessage, const NarrowString &newLogMessage )
        : m_userMessage(userMessage), m_logMessage(newLogMessage)
  {
	  /**
      if (!ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
    	  ESAPI.intrusionDetector().addException(this);
      }*/
  }

  EnterpriseSecurityException::EnterpriseSecurityException(const WideString& userMessage, const WideString& logMessage)
    : m_userMessage(TextConvert::WideToNarrowNoThrow(userMessage)), m_logMessage(TextConvert::WideToNarrowNoThrow(logMessage))
  {    
  }

  NarrowString EnterpriseSecurityException::getUserMessage() const
  {
    ASSERT( !m_userMessage.empty() );
    return m_userMessage;
  }

  const char* EnterpriseSecurityException::what() const throw()
  {
    ASSERT( !m_userMessage.empty() );
    return m_userMessage.c_str();
  }

  NarrowString EnterpriseSecurityException::getLogMessage() const
  {
    ASSERT( !m_logMessage.empty() );
	  return m_logMessage;
  }
} // esapi
