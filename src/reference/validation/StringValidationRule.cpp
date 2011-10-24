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
	  if (encoder==nullptr) throw NullPointerException("encoder has null pointer");

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
	  //if (encoder==nullptr) throw NullPointerException("encoder has null pointer");

	  String data = L"";

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
	  if (&errorList==nullptr) throw NullPointerException("errorList has null pointer");

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
		  throw IllegalArgumentException("Pattern cannot be null");
	  }

	  this->whitelistPatterns.insert(pattern);
  }

  void StringValidationRule::addBlacklistPattern(const String &pattern) {
	  if (pattern.compare(L"")==0) {
		  throw IllegalArgumentException("Pattern cannot be null");
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

  String StringValidationRule::checkWhitelist(const String &context, const String &input, const String &orig)
  {
      NarrowString ninput = TextConvert::WideToNarrow(input);
	  std::set<String>::iterator it = whitelistPatterns.begin();

	  for (; it!= whitelistPatterns.end(); it++) {
          const NarrowString npattern(TextConvert::WideToNarrow(*it));
		  const boost::regex nre(npattern);

		  if(!boost::regex_match(ninput,nre)) {
			  StringStream userMessage;			  
			  userMessage << context << L": Invalid input. Please conform to regex '";
              userMessage << *it << L"' with a maximum length of ";
              userMessage << maxLength;

              StringStream logMessage;
			  logMessage << L"Invalid input: context=" << context << L", type (" << getTypeName();
              logMessage << L") =" << *it << L", input=" << input;
              logMessage << (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? L"" : L", orig=" + orig);

			  throw ValidationException( userMessage.str(), logMessage.str(), context );
		  }
	  }

	  return input;
  }

  String StringValidationRule::checkWhitelist(const String &context, const String &input) {
	  return checkWhitelist(context, input, input);
  }

  String StringValidationRule::checkBlacklist(const String &context, const String &input, const String &orig)
  {
      NarrowString ninput = TextConvert::WideToNarrow(input);
	  std::set<String>::iterator it = blacklistPatterns.begin();

	  for (; it!= blacklistPatterns.end(); it++)
      {
          const NarrowString npattern(TextConvert::WideToNarrow(*it));
		  const boost::regex nre(npattern);

		  if(boost::regex_match(ninput,nre)) {
			  StringStream userMessage;
			  StringStream logMessage;
			  userMessage << context << L": Invalid input. Dangerous input matching " << *it + L" detected.";
			  logMessage << L"Dangerous input: context=" << context << L", type(L" + getTypeName() + L")=" + *it + L", input=" + input + (/*NullSafe.equals(orig,input)*/(input.compare(orig)==0) ? L"" : L", orig=" + orig);
			  throw ValidationException( userMessage.str(), logMessage.str(), context );
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
		  userMessage << context << L": Invalid input. The minimum length of " << minLength << L" characters was not met.";
		  logMessage << L"Input does not meet the minimum length of " << minLength << L" by " << (minLength - input.size()) << L" characters: context=" << context << L", type=" << getTypeName() << L"), input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? L"" : L", orig=" + orig);
		  throw ValidationException( userMessage.str(), logMessage.str(), context );
	  }

	  if (input.size() > maxLength) {
		  StringStream userMessage;
		  StringStream logMessage;
		  userMessage << context << L": Invalid input. The maximum length of " << maxLength << L" characters was exceeded.";
		  logMessage << L"Input exceeds maximum allowed length of " << maxLength << L" by " << (input.size()-maxLength) << L" characters: context=" << context << L", type=" << getTypeName() << L", orig=" << orig <<", input=" << input;
		  throw ValidationException( userMessage.str(), logMessage.str(), context );
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
	  userMessage << context + L": Input required.";
	  logMessage << L"Input required: context=" << context << L", input=" << input << (/*NullSafe.equals(input,orig)*/(input.compare(orig)==0) ? L"" : L", orig=" + orig);
	  throw ValidationException(userMessage.str(), logMessage.str(), context );
  }

  String StringValidationRule::checkEmpty(const String &context, const String &input) {
	  return checkEmpty(context, input, input);
  }
} //esapi
