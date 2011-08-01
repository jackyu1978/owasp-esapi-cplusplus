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

#include "esapi/errors/EnterpriseSecurityException.h"

esapi::EnterpriseSecurityException::EnterpriseSecurityException(std::string userMessage, std::string newLogMessage): std::runtime_error( userMessage )
{
	this->logMessage = newLogMessage;
	/*
    if (!ESAPI.securityConfiguration().getDisableIntrusionDetection()) {
    	ESAPI.intrusionDetector().addException(this);
    }*/
}

std::string esapi::EnterpriseSecurityException::getUserMessage()
{
	return this->what();
}

std::string esapi::EnterpriseSecurityException::getLogMessage()
{
	return this->logMessage;
}
