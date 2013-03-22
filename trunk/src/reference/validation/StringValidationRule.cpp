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
#include "util/TextConvert.h"
#include "errors/UnsupportedOperationException.h"
#include "errors/NullPointerException.h"
#include "errors/ValidationException.h"
#include "EncoderConstants.h"

#include <limits.h>
#include <sstream>

#if defined(_WIN32)
    #if defined(_WINDLL)
        #define BOOST_REGEX_DYN_LINK
    #endif
#else
    #define BOOST_REGEX_DYN_LINK
#endif
#include <boost/regex.hpp>

namespace esapi
{
  StringValidationRule::StringValidationRule(const NarrowString & typeName)
	  : BaseValidationRule<String>(typeName), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
  {
	  //setEncoder( ESAPI.encoder() );
	  setTypeName( typeName );
  }

  StringValidationRule::StringValidationRule(const NarrowString & typeName, Encoder* encoder)
	  : BaseValidationRule<String>(typeName, encoder), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
  {
	  ASSERT(encoder);
	  if (encoder==nullptr) throw NullPointerException("encoder has null pointer");

	  setEncoder( encoder );
	  setTypeName( typeName );
  }

  StringValidationRule::StringValidationRule(const NarrowString &typeName, Encoder* encoder, const NarrowString & whitelistPattern)
	  : BaseValidationRule<String>(typeName, encoder), whitelistPatterns(), blacklistPatterns(), minLength(0), maxLength(INT_MAX), validateInputAndCanonical(true)
  {
	  addWhitelistPattern(whitelistPattern);
  }

  String StringValidationRule::getValid(const NarrowString &context, const NarrowString &input) {
	  //ASSERT(encoder);
	  //if (encoder==nullptr) throw NullPointerException("encoder has null pointer");

	  String data = "";

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
		  //data = encoder->canonicalize( input );
		  data = input; // HACK! TODO: remove after locater class works.

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

  String StringValidationRule::getValid( const NarrowString &context, const NarrowString &input, ValidationErrorList &errorList ) {
	  ASSERT(&errorList);
	  if (&errorList==nullptr) throw NullPointerException("errorList has null pointer");

	  String valid = "";

	  try {
		  valid = this->getValid( context, input );
	  } catch (ValidationException &e) {
		  errorList.addError(context, &e);
	  }
	  return valid;
  }

  String StringValidationRule::sanitize(const NarrowString &context, const NarrowString &input) {
	  return whitelist( input, EncoderConstants::ALPHANUMERICS );
  }

  void StringValidationRule::addWhitelistPattern(const NarrowString & pattern) {
	  if (pattern.compare("")==0) {
		  throw IllegalArgumentException("Pattern cannot be nu");
	  }

	  const boost::regex nre(pattern);
	  this->whitelistPatterns.insert(pattern);
  }

  void StringValidationRule::addBlacklistPattern(const NarrowString &pattern) {
	  if (pattern.compare("")==0) {
		  throw IllegalArgumentException("Pattern cannot be nu");
	  }

	  const boost::regex nre(pattern);
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

  String StringValidationRule::checkWhitelist(const NarrowString &context, const NarrowString &input, const NarrowString &orig)
  {
	  std::set<String>::iterator it = whitelistPatterns.begin();

	  for (; it!= whitelistPatterns.end(); it++) {
		  const boost::regex nre(*it);
		  if(!boost::regex_match(input,nre)) {
			  StringStream userMessage;			  
			  userMessage << context << ": Invalid input. Please conform to regex '";
              userMessage << *it << "' with a maximum length of ";
              userMessage << maxLength;

              StringStream logMessage;
			  logMessage << "Invalid input: context=" << context << ", type (" << getTypeName();
              logMessage << ") =" << *it << ", input=" << input;
              logMessage << (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);

			  throw ValidationException( userMessage.str(), logMessage.str(), context );
		  }
	  }

	  return input;
  }

  String StringValidationRule::checkWhitelist(const NarrowString &context, const NarrowString &input) {
	  return checkWhitelist(context, input, input);
  }

  String StringValidationRule::checkBlacklist(const NarrowString &context, const NarrowString &input, const NarrowString &orig)
  {
	  std::set<String>::iterator it = blacklistPatterns.begin();

	  for (; it!= blacklistPatterns.end(); it++)
      {
		  const boost::regex nre(*it);

		  if(boost::regex_match(input,nre)) {
			  StringStream userMessage;
			  StringStream logMessage;
			  userMessage << context << ": Invalid input. Dangerous input matching " << *it + " detected.";
			  logMessage << "Dangerous input: context=" << context << ", type(" + getTypeName() + ")=" + *it + ", input=" + input + (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
			  throw ValidationException( userMessage.str(), logMessage.str(), context );
		  }
	  }

	  return input;

  }

  String StringValidationRule::checkBlacklist(const NarrowString &context, const NarrowString &input) {
	  return checkBlacklist(context, input, input);
  }

  String StringValidationRule::checkLength(const NarrowString &context, const NarrowString &input, const NarrowString &orig) {
	  if (input.size() < minLength) {
		  StringStream userMessage;
		  StringStream logMessage;
		  userMessage << context << ": Invalid input. The minimum length of " << minLength << " characters was not met.";
		  logMessage << "Input does not meet the minimum length of " << minLength << " by " << (minLength - input.size()) << " characters: context=" << context << ", type=" << getTypeName() << "), input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
		  throw ValidationException( userMessage.str(), logMessage.str(), context );
	  }

	  if (input.size() > maxLength) {
		  StringStream userMessage;
		  StringStream logMessage;
		  userMessage << context << ": Invalid input. The maximum length of " << maxLength << " characters was exceeded.";
		  logMessage << "Input exceeds maximum allowed length of " << maxLength << " by " << (input.size()-maxLength) << " characters: context=" << context << ", type=" << getTypeName() << ", orig=" << orig <<", input=" << input;
		  throw ValidationException( userMessage.str(), logMessage.str(), context );
	  }

	  return input;
  }

  String StringValidationRule::checkLength(const NarrowString &context, const NarrowString &input) {
	  return checkLength(context, input, input);
  }

  String StringValidationRule::checkEmpty(const NarrowString &context, const NarrowString &input, const NarrowString &orig) {
	  if(!input.empty())
		  return input;
	  if(allowNull)
		  return "";

	  StringStream userMessage;
	  StringStream logMessage;
	  userMessage << context + ": Input required.";
	  logMessage << "Input required: context=" << context << ", input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? "" : ", orig=" + orig);
	  throw ValidationException(userMessage.str(), logMessage.str(), context );
  }

  String StringValidationRule::checkEmpty(const NarrowString &context, const NarrowString &input) {
	  return checkEmpty(context, input, input);
  }
} //esapi
