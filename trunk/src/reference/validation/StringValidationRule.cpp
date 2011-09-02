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
#include "EncoderConstants.h"

#include <limits.h>
#include <sstream>

#define BOOST_REGEX_DYN_LINK
#include <boost/regex.hpp>

esapi::StringValidationRule::StringValidationRule(const std::string & typeName)
	: BaseValidationRule<std::string>(typeName), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
{

}

esapi::StringValidationRule::StringValidationRule(const std::string & typeName, Encoder* encoder)
	: BaseValidationRule<std::string>(typeName, encoder), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
{

}

esapi::StringValidationRule::StringValidationRule(const std::string &typeName, Encoder* encoder, const std::string & whitelistPattern)
	: BaseValidationRule<std::string>(typeName, encoder), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
{
	addWhitelistPattern(whitelistPattern);
}

std::string esapi::StringValidationRule::getValid(const std::string &context, const std::string &input) throw (ValidationException) {

		std::string data = "";

		// checks on input itself

		// check for empty/null
		if(checkEmpty(context, input).compare("")==0)
			return "";

		if (validateInputAndCanonical)
		{
			//first validate pre-canonicalized data

			// check length
			checkLength(context, input);

			// check whitelist patterns
			checkWhitelist(context, input);

			// check blacklist patterns
			checkBlacklist(context, input);

			// canonicalize
			data = encoder->canonicalize( input );

		} else {

			//skip canonicalization
			data = input;
		}

		// check for empty/null
		if(checkEmpty(context, data, input).compare("")==0)
			return "";

		// check length
		checkLength(context, data, input);

		// check whitelist patterns
		checkWhitelist(context, data, input);

		// check blacklist patterns
		checkBlacklist(context, data, input);

		// validation passed
		return data;
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

std::string esapi::StringValidationRule::sanitize(const std::string &context, const std::string &input) {
	return whitelist( input, EncoderConstants::ALPHANUMERICS );
}

void esapi::StringValidationRule::addWhitelistPattern(const std::string & pattern) throw (esapi::IllegalArgumentException) {
	if (pattern.compare("")==0) {
		throw new IllegalArgumentException("Pattern cannot be null");
	}

	this->whitelistPatterns.insert(pattern);
}

void esapi::StringValidationRule::addBlacklistPattern(const std::string &pattern) throw (esapi::IllegalArgumentException) {
	if (pattern.compare("")==0) {
		throw new IllegalArgumentException("Pattern cannot be null");
	}

	this->blacklistPatterns.insert(pattern);
}

void esapi::StringValidationRule::setMinimumLength(int length) {
	this->minLength = length;
}

void esapi::StringValidationRule::setMaximumLength(int length) {
	this->maxLength = length;
}

void esapi::StringValidationRule::setValidateInputAndCanonical(bool flag) {
	this->validateInputAndCanonical = flag;
}

std::string esapi::StringValidationRule::checkWhitelist(const std::string &context, const std::string &input, const std::string &orig) throw (ValidationException) {
	std::set<std::string>::iterator it;
	for (it=whitelistPatterns.begin(); it!= whitelistPatterns.end(); it++) {
		const boost::regex re(*it);
		if(!boost::regex_match(input,re)) {
			std::stringstream userMessage;
			std::stringstream logMessage;
			userMessage << context << ": Invalid input. Please conform to regex " << *it << " with a maximum length of " + maxLength;
			logMessage << "Invalid input: context=" << context << ", type(" << getTypeName() << ")=" << *it << ", input=" << input << (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
			throw new ValidationException( userMessage.str(), logMessage.str(), context );
		}
	}
	return input;
}

std::string esapi::StringValidationRule::checkWhitelist(const std::string &context, const std::string &input) throw (ValidationException) {
	return checkWhitelist(context, input, input);
}

std::string esapi::StringValidationRule::checkBlacklist(const std::string &context, const std::string &input, const std::string &orig) throw (ValidationException) {
	std::set<std::string>::iterator it;
	for (it=blacklistPatterns.begin(); it!= blacklistPatterns.end(); it++) {
		const boost::regex re(*it);
		if(!boost::regex_match(input,re)) {
			std::stringstream userMessage;
			std::stringstream logMessage;
			userMessage << context << ": Invalid input. Dangerous input matching " << *it + " detected.";
			logMessage << "Dangerous input: context=" << context << ", type(" + getTypeName() + ")=" + *it + ", input=" + input + (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
			throw new ValidationException( userMessage.str(), logMessage.str(), context );
		}
	}
	return input;

}

std::string esapi::StringValidationRule::checkBlacklist(const std::string &context, const std::string &input) throw (ValidationException) {
	return checkBlacklist(context, input, input);
}

std::string esapi::StringValidationRule::checkLength(const std::string &context, const std::string &input, const std::string &orig) throw (ValidationException) {
	if (input.size() < minLength) {
		std::stringstream userMessage;
		std::stringstream logMessage;
		userMessage << context << ": Invalid input. The minimum length of " << minLength << " characters was not met.";
		logMessage << "Input does not meet the minimum length of " << minLength << " by " << (minLength - input.size()) << " characters: context=" << context << ", type=" << getTypeName() << "), input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
		throw new ValidationException( userMessage.str(), logMessage.str(), context );
	}

	if (input.size() > maxLength) {
		std::stringstream userMessage;
		std::stringstream logMessage;
		userMessage << context << ": Invalid input. The maximum length of " << maxLength << " characters was exceeded.";
		logMessage << "Input exceeds maximum allowed length of " << maxLength << " by " << (input.size()-maxLength) << " characters: context=" << context << ", type=" << getTypeName() << ", orig=" << orig <<", input=" << input;
		throw new ValidationException( userMessage.str(), logMessage.str(), context );
	}

	return input;
}

std::string esapi::StringValidationRule::checkLength(const std::string &context, const std::string &input) throw (ValidationException) {
	return checkLength(context, input, input);
}

std::string esapi::StringValidationRule::checkEmpty(const std::string &context, const std::string &input, const std::string &orig) throw (ValidationException) {
	if(!input.empty())
		return input;
	if(allowNull)
		return "";

	std::stringstream userMessage;
	std::stringstream logMessage;
	userMessage << context + ": Input required.";
	logMessage << "Input required: context=" << context << "), input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
	throw new ValidationException(userMessage.str(), logMessage.str(), context );
}

std::string esapi::StringValidationRule::checkEmpty(const std::string &context, const std::string &input) throw (ValidationException) {
	return checkEmpty(context, input, input);
}
