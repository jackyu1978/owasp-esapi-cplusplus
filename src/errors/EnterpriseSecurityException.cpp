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

#include "errors/EnterpriseSecurityException.h"

esapi::EnterpriseSecurityException::EnterpriseSecurityException(const std::string &userMessage, const std::string &newLogMessage )
  : userMessage( userMessage ), logMessage( newLogMessage )
{
	/**
    if (!ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
    	ESAPI.intrusionDetector().addException(this);
    }*/
}

std::string esapi::EnterpriseSecurityException::getUserMessage() const
{
	return this->userMessage;
}

const char* esapi::EnterpriseSecurityException::what() const throw()
{
	return this->userMessage.c_str();
}

std::string esapi::EnterpriseSecurityException::getLogMessage() const
{
	return this->logMessage;
}
