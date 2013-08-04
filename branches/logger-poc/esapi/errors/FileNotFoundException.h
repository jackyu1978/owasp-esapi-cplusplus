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
#include <typeinfo>
#include <string>

namespace esapi {

class ESAPI_EXPORT FileNotFoundException: public EnterpriseSecurityException {
public:
	explicit FileNotFoundException(const WideString &message) :
		EnterpriseSecurityException(message, message) {
	}
	explicit FileNotFoundException(const WideString &userMessage,
			const WideString &logMessage) :
		EnterpriseSecurityException(userMessage, logMessage) {
	}

	explicit FileNotFoundException(const NarrowString &message) :
		EnterpriseSecurityException(message, message) {
	}
	explicit FileNotFoundException(const NarrowString &userMessage,
			const NarrowString &logMessage) :
		EnterpriseSecurityException(userMessage, logMessage) {
	}
};

} // NAMESPACE

