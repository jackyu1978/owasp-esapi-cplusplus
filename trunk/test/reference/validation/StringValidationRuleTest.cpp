/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Daniel Amodio, dan.amodio@aspectsecurity.com
 *
 */

#include "EsapiCommon.h"

#if defined(ESAPI_OS_WINDOWS_STATIC)
// do not enable BOOST_TEST_DYN_LINK
#elif defined(ESAPI_OS_WINDOWS_DYNAMIC)
# define BOOST_TEST_DYN_LINK
#elif defined(ESAPI_OS_WINDOWS)
# error "For Windows, ESAPI_OS_WINDOWS_STATIC or ESAPI_OS_WINDOWS_DYNAMIC must be defined"
#else
# define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;
using esapi::NarrowString;

#include <map>
#include <set>
#include <exception>
#include <boost/regex.hpp>

#include "reference/validation/StringValidationRule.h"
#include "errors/ValidationException.h"
#include "errors/IllegalArgumentException.h"
#include "ValidationErrorList.h"
using esapi::ValidationErrorList;
using esapi::StringValidationRule;
using esapi::ValidationException;
using esapi::IllegalArgumentException;

#include "util/TextConvert.h"
using esapi::TextConvert;

// ABI Compatibility problem
#if !defined(_GLIBCXX_DEBUG)

BOOST_AUTO_TEST_CASE( BoostRegexTest) {
	const boost::regex re("^[a-zA-Z]*");
	BOOST_CHECK(boost::regex_match("asdf",re));
	BOOST_CHECK(!boost::regex_match("234SDFG",re));
}

BOOST_AUTO_TEST_CASE( StringValidationRuleTestWhitelistPattern) {

	StringValidationRule validationRule("Alphabetic");
	validationRule.setValidateInputAndCanonical(false);

#if !defined(ESAPI_BUILD_RELEASE)
	BOOST_CHECK(validationRule.checkEmpty("", "asdf").compare("asdf")==0);

	BOOST_CHECK(validationRule.checkLength("", "asdf").compare("asdf")==0);

	BOOST_CHECK(validationRule.checkWhitelist("", "asdf").compare("asdf")==0);

	BOOST_CHECK(validationRule.checkBlacklist("", "asdf").compare("asdf")==0);
#endif

	try {
		BOOST_CHECK(validationRule.getValid("", "asdf").compare("asdf")==0);
	} catch(ValidationException& ve) {
        NarrowString msg = NarrowString("Exception should not have been thrown: ") + ve.getLogMessage();
		BOOST_FAIL(msg);
	}


	validationRule.addWhitelistPattern("^[a-zA-Z]*");


	try {
		validationRule.getValid("", "Magnum44");
		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (ValidationException& ve) {
		BOOST_CHECK(ve.getLogMessage().compare("")!=0); // should not be empty
	}


	try {
		BOOST_CHECK(validationRule.getValid("", "MagnumPI").compare("MagnumPI")==0);
	} catch(ValidationException& ve) {
        NarrowString msg = NarrowString("Exception should not have been thrown: ") + ve.getLogMessage();
		BOOST_FAIL(msg);
	}

}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelistPattern_Invalid) {

	StringValidationRule validationRule("");

	//null white list patterns throw IllegalArgumentException
	try {
		String pattern = "";
		validationRule.addWhitelistPattern(pattern);
		BOOST_FAIL("Expected Exception not thrown");
	} catch (IllegalArgumentException& ie) {
		BOOST_CHECK(!ie.getUserMessage().empty());
	}


	//invalid white list patterns throw PatternSyntaxException
	try {
		String pattern = "_][0}[";
		validationRule.addWhitelistPattern(pattern);

		//validationRule.getValid("", "test");

		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (std::exception &e) {
		BOOST_CHECK(e.what()!=0);
	}

}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelist){
	StringValidationRule validationRule("");

	std::set<Char> whitelistArray;
	whitelistArray.insert(L'a');
	whitelistArray.insert(L'b');
	whitelistArray.insert(L'c');

	BOOST_CHECK(validationRule.whitelist("12345abcdef", whitelistArray).compare("abc")==0);
}


BOOST_AUTO_TEST_CASE( StringValidationRuleTestBlacklistPattern) {

	StringValidationRule validationRule("NoAngleBrackets");

	BOOST_CHECK(validationRule.getValid("", "beg <script> end").compare("beg <script> end")==0);

	validationRule.addBlacklistPattern("^.*(<|>).*");

	try {
		validationRule.getValid("", "beg <script> end");
		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (ValidationException &ve) {
		BOOST_CHECK(!ve.getUserMessage().empty());
	}
	BOOST_CHECK(validationRule.getValid("", "beg script end").compare("beg script end")==0);
}


BOOST_AUTO_TEST_CASE(StringValidationRuleTestBlacklistPattern_Invalid) {

	StringValidationRule validationRule("");

	//null black list patterns throw IllegalArgumentException
	try {
		String pattern = "";
		validationRule.addBlacklistPattern(pattern);
		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (IllegalArgumentException &ie) {
		BOOST_CHECK(!ie.getUserMessage().empty());
	}

	//invalid black list patterns throw PatternSyntaxException
	try {
		String pattern = "_][0}[";
		validationRule.addBlacklistPattern(pattern);
		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (std::exception &e) {
		BOOST_CHECK(e.what()!=0);
	}
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestCheckLengths) {

	StringValidationRule validationRule("Max12_Min2");
	validationRule.setMinimumLength(2);
	validationRule.setMaximumLength(12);

	BOOST_CHECK(validationRule.isValid("", "12"));
	BOOST_CHECK(validationRule.isValid("", "123456"));
	BOOST_CHECK(validationRule.isValid("", "ABCDEFGHIJK"));

	BOOST_CHECK(!validationRule.isValid("", "1"));
	BOOST_CHECK(!validationRule.isValid("", "ABCDEFGHIJKLM"));

	ValidationErrorList errorList;
	BOOST_CHECK(validationRule.getValid("", "1234567890", errorList).compare("1234567890")==0);
	BOOST_CHECK(errorList.size()==0);
	BOOST_CHECK(validationRule.getValid("test", "123456789012345", errorList).compare("")==0);
	BOOST_CHECK(errorList.size()==1);
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestAllowNull) {

	StringValidationRule validationRule("");

	BOOST_CHECK(!validationRule.isAllowNull());
	BOOST_CHECK(!validationRule.isValid("", ""));

	validationRule.setAllowNull(true);
	BOOST_CHECK(validationRule.isAllowNull());
	BOOST_CHECK(validationRule.isValid("", ""));
}

#endif // !defined(_GLIBCXX_DEBUG)
