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

#include "esapi/errors/ValidationException.h"
#include "esapi/errors/EnterpriseSecurityException.h"
#include <string>

esapi::ValidationException::ValidationException(std::string userMessage, std::string logMessage, std::string context) :
				esapi::EnterpriseSecurityException(userMessage, logMessage)
{
	setContext(context);
}

std::string esapi::ValidationException::getContext() {
	return this->context;
}

void esapi::ValidationException::setContext(std::string newContext) {
	this->context = newContext;
}
