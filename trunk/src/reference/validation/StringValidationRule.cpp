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
#include "errors/NullPointerException.h"
#include "errors/ValidationException.h"
#include "EncoderConstants.h"

#include <limits.h>
#include <sstream>

#define BOOST_REGEX_DYN_LINK
#include <boost/regex.hpp>

namespace esapi
{
  StringValidationRule::StringValidationRule(const String & typeName)
	  : BaseValidationRule<String>(typeName), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
  {
	  //setEncoder( ESAPI.encoder() );
	  setTypeName( typeName );
  }

  StringValidationRule::StringValidationRule(const String & typeName, Encoder* encoder)
	  : BaseValidationRule<String>(typeName, encoder), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
  {
	  ASSERT(encoder);
	  if (encoder==nullptr) throw new NullPointerException(L"encoder has null pointer");

	  setEncoder( encoder );
	  setTypeName( typeName );
  }

  StringValidationRule::StringValidationRule(const String &typeName, Encoder* encoder, const String & whitelistPattern)
	  : BaseValidationRule<String>(typeName, encoder), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
  {
	  addWhitelistPattern(whitelistPattern);
  }

  String StringValidationRule::getValid(const String &context, const String &input) {
	  //ASSERT(encoder);
	  //if (encoder==nullptr) throw new NullPointerException(L"encoder has null pointer");

	  String data = "";

	  // checks on input itself

	  // check for empty/null
	  if(checkEmpty(context, input).compare(L"")==0)
		  return L"";

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
		  //data = encoder->canonicalize( input );
		  data = input; // HACK! TODO: remove after locater class works.

	  } else {

		  //skip canonicalization
		  data = input;
	  }

	  // check for empty/null
	  if(checkEmpty(context, data, input).compare(L"")==0)
		  return L"";

	  // check length
	  checkLength(context, data, input);

	  // check whitelist patterns
	  checkWhitelist(context, data, input);

	  // check blacklist patterns
	  checkBlacklist(context, data, input);

	  // validation passed
	  return data;
  }

  String StringValidationRule::getValid( const String &context, const String &input, ValidationErrorList &errorList ) {
	  ASSERT(&errorList);
	  if (&errorList==nullptr) throw new NullPointerException(L"errorList has null pointer");

	  String valid;
	  try {
		  valid = this->getValid( context, input );
	  } catch (ValidationException &e) {
		  errorList.addError(context, &e);
	  }
	  return valid;
  }

  String StringValidationRule::sanitize(const String &context, const String &input) {
	  return whitelist( input, EncoderConstants::ALPHANUMERICS );
  }

  void StringValidationRule::addWhitelistPattern(const String & pattern) {
	  if (pattern.compare(L"")==0) {
		  throw new IllegalArgumentException(L"Pattern cannot be null");
	  }

	  this->whitelistPatterns.insert(pattern);
  }

  void StringValidationRule::addBlacklistPattern(const String &pattern) {
	  if (pattern.compare(L"")==0) {
		  throw new IllegalArgumentException(L"Pattern cannot be null");
	  }

	  this->blacklistPatterns.insert(pattern);
  }

  void StringValidationRule::setMinimumLength(int length) {
	  this->minLength = length;
  }

  void StringValidationRule::setMaximumLength(int length) {
	  this->maxLength = length;
  }

  void StringValidationRule::setValidateInputAndCanonical(bool flag) {
	  this->validateInputAndCanonical = flag;
  }

  String StringValidationRule::checkWhitelist(const String &context, const String &input, const String &orig) {
	  std::set<String>::iterator it;

	  if (!whitelistPatterns.empty()) {
		  for (it=whitelistPatterns.begin(); it!= whitelistPatterns.end(); it++) {
			  const boost::regex re(*it);
			  if(!boost::regex_match(input,re)) {
				  StringStream userMessage;
				  StringStream logMessage;
				  userMessage << context << ": Invalid input. Please conform to regex " << *it << " with a maximum length of " + maxLength;
				  logMessage << "Invalid input: context=" << context << ", type(L" << getTypeName() << ")=" << *it << ", input=" << input << (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
				  throw new ValidationException( userMessage.str(), logMessage.str(), context );
			  }
		  }
	  }

	  return input;
  }

  String StringValidationRule::checkWhitelist(const String &context, const String &input) {
	  return checkWhitelist(context, input, input);
  }

  String StringValidationRule::checkBlacklist(const String &context, const String &input, const String &orig) {
	  std::set<String>::iterator it;

	  if (!blacklistPatterns.empty()) {
		  for (it=blacklistPatterns.begin(); it!= blacklistPatterns.end(); it++) {
			  const boost::regex re(*it);
			  if(!boost::regex_match(input,re)) {
				  StringStream userMessage;
				  StringStream logMessage;
				  userMessage << context << ": Invalid input. Dangerous input matching " << *it + " detected.";
				  logMessage << "Dangerous input: context=" << context << ", type(L" + getTypeName() + ")=" + *it + ", input=" + input + (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
				  throw new ValidationException( userMessage.str(), logMessage.str(), context );
			  }
		  }
	  }

	  return input;

  }

  String StringValidationRule::checkBlacklist(const String &context, const String &input) {
	  return checkBlacklist(context, input, input);
  }

  String StringValidationRule::checkLength(const String &context, const String &input, const String &orig) {
	  if (input.size() < minLength) {
		  StringStream userMessage;
		  StringStream logMessage;
		  userMessage << context << ": Invalid input. The minimum length of " << minLength << " characters was not met.";
		  logMessage << "Input does not meet the minimum length of " << minLength << " by " << (minLength - input.size()) << " characters: context=" << context << ", type=" << getTypeName() << "), input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
		  throw new ValidationException( userMessage.str(), logMessage.str(), context );
	  }

	  if (input.size() > maxLength) {
		  StringStream userMessage;
		  StringStream logMessage;
		  userMessage << context << ": Invalid input. The maximum length of " << maxLength << " characters was exceeded.";
		  logMessage << "Input exceeds maximum allowed length of " << maxLength << " by " << (input.size()-maxLength) << " characters: context=" << context << ", type=" << getTypeName() << ", orig=" << orig <<", input=" << input;
		  throw new ValidationException( userMessage.str(), logMessage.str(), context );
	  }

	  return input;
  }

  String StringValidationRule::checkLength(const String &context, const String &input) {
	  return checkLength(context, input, input);
  }

  String StringValidationRule::checkEmpty(const String &context, const String &input, const String &orig) {
	  if(!input.empty())
		  return input;
	  if(allowNull)
		  return L"";

	  StringStream userMessage;
	  StringStream logMessage;
	  userMessage << context + ": Input required.";
	  logMessage << "Input required: context=" << context << "), input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
	  throw new ValidationException(userMessage.str(), logMessage.str(), context );
  }

  String StringValidationRule::checkEmpty(const String &context, const String &input) {
	  return checkEmpty(context, input, input);
  }
} //esapi
