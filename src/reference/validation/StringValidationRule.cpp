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
 */

#include "reference/validation/StringValidationRule.h"
#include "errors/UnsupportedOperationException.h"

esapi::StringValidationRule::StringValidationRule(const std::string &) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

esapi::StringValidationRule::StringValidationRule(const std::string &, Encoder*) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

esapi::StringValidationRule::StringValidationRule(const std::string &, Encoder*, const std::string &) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::getValid(const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::getValid( const std::string &context, const std::string &input, ValidationErrorList &errorList ) throw (ValidationException) {
		std::string valid;
		try {
			valid = this->getValid( context, input );
		} catch (ValidationException &e) {
			errorList.addError(context, &e);
		}
		return valid;
}

std::string esapi::StringValidationRule::sanitize(const std::string &, const std::string &) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

void esapi::StringValidationRule::addWhitelistPattern(const std::string &) throw (esapi::IllegalArgumentException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

void esapi::StringValidationRule::addBlacklistPattern(const std::string &) throw (esapi::IllegalArgumentException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

void esapi::StringValidationRule::setMinimumLength(int) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

void esapi::StringValidationRule::setMaximumLength(int) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

void esapi::StringValidationRule::setValidateInputAndCanonical(bool) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkWhitelist(const std::string &, const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkWhitelist(const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkBlacklist(const std::string &, const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkBlacklist(const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkLength(const std::string &, const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkLength(const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkEmpty(const std::string &, const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}

std::string esapi::StringValidationRule::checkEmpty(const std::string &, const std::string &) throw (ValidationException) {
	throw new UnsupportedOperationException("This operation has not yet been implemented");
}
