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
#include "errors/EnterpriseSecurityException.h"

namespace esapi
{
EnterpriseSecurityException::EnterpriseSecurityException(const String &userMessage, const String &newLogMessage )
  : std::runtime_error( userMessage.c_str() ), logMessage( newLogMessage )
{
	/**
    if (!ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
    	ESAPI.intrusionDetector().addException(this);
    }*/
}

String EnterpriseSecurityException::getUserMessage() const
{
	return std::runtime_error::what();
}

const Char* EnterpriseSecurityException::what() const throw()
{
	return std::runtime_error::what();
}

String EnterpriseSecurityException::getLogMessage() const
{
	return this->logMessage;
}

} // esapi
