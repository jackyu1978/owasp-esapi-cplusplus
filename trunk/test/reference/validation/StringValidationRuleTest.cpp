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

#define BOOST_TEST_DYN_LINK
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
using esapi::StringValidationRule;
using esapi::ValidationException;

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

	StringValidationRule validationRule(L"Alphabetic");
	validationRule.setValidateInputAndCanonical(false);

#if !defined(ESAPI_BUILD_RELEASE)
	BOOST_CHECK(validationRule.checkEmpty(L"", L"asdf").compare(L"asdf")==0);

	BOOST_CHECK(validationRule.checkLength(L"", L"asdf").compare(L"asdf")==0);

	BOOST_CHECK(validationRule.checkWhitelist(L"", L"asdf").compare(L"asdf")==0);

	BOOST_CHECK(validationRule.checkBlacklist(L"", L"asdf").compare(L"asdf")==0);
#endif

	try {
		BOOST_CHECK(validationRule.getValid(L"", L"asdf").compare(L"asdf")==0);
	} catch(ValidationException& ve) {
        NarrowString msg = NarrowString("Exception should not have been thrown: ") + ve.getLogMessage();
		BOOST_FAIL(msg);
	}


	validationRule.addWhitelistPattern(L"^[a-zA-Z]*");

	/*
	try {
		validationRule.getValid(L"", L"Magnum44");
		BOOST_FAIL(L"Expected Exception not thrown");
	}
	catch (ValidationException& ve) {
		BOOST_CHECK(!ve.getContext().empty()); // should not be empty
	}*/


	try {
		BOOST_CHECK(validationRule.getValid(L"", L"MagnumPI").compare(L"MagnumPI")==0);
	} catch(ValidationException& ve) {
        NarrowString msg = NarrowString("Exception should not have been thrown: ") + ve.getLogMessage();
		BOOST_FAIL(msg);
	}

}
/*
BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelistPattern_Invalid) {

	StringValidationRule validationRule = new StringValidationRule(L"");

	//null white list patterns throw IllegalArgumentException
	try {
		String pattern = null;
		validationRule.addWhitelistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	try {
		java.util.regex.Pattern pattern = null;
		validationRule.addWhitelistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	//invalid white list patterns throw PatternSyntaxException
	try {
		String pattern = "_][0}[";
		validationRule.addWhitelistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelist){
	StringValidationRule validationRule = new StringValidationRule(L"");

	char[] whitelistArray = new char[] {'a', 'b', 'c'};
	Assert.assertEquals(L"abc", validationRule.whitelist(L"12345abcdef", whitelistArray));
}

BOOST_AUTO_TEST_CASE( StringValidationRuleTestBlacklistPattern) {

	StringValidationRule validationRule = new StringValidationRule(L"NoAngleBrackets");

	Assert.assertEquals(L"beg <script> end", validationRule.getValid(L"", L"beg <script> end"));
	validationRule.addBlacklistPattern(L"^.*(<|>).*");
	try {
		validationRule.getValid(L"", L"beg <script> end");
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (ValidationException ve) {
		Assert.assertNotNull(ve.getMessage());
	}
	Assert.assertEquals(L"beg script end", validationRule.getValid(L"", L"beg script end"));
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestBlacklistPattern_Invalid) {

	StringValidationRule validationRule = new StringValidationRule(L"");

	//null black list patterns throw IllegalArgumentException
	try {
		String pattern = null;
		validationRule.addBlacklistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	try {
		java.util.regex.Pattern pattern = null;
		validationRule.addBlacklistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	//invalid black list patterns throw PatternSyntaxException
	try {
		String pattern = "_][0}[";
		validationRule.addBlacklistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestCheckLengths) {

	StringValidationRule validationRule = new StringValidationRule(L"Max12_Min2");
	validationRule.setMinimumLength(2);
	validationRule.setMaximumLength(12);

	Assert.assertTrue(validationRule.isValid(L"", L"12"));
	Assert.assertTrue(validationRule.isValid(L"", L"123456"));
	Assert.assertTrue(validationRule.isValid(L"", L"ABCDEFGHIJKL"));

	Assert.assertFalse(validationRule.isValid(L"", L"1"));
	Assert.assertFalse(validationRule.isValid(L"", L"ABCDEFGHIJKLM"));

	ValidationErrorList errorList = new ValidationErrorList();
	Assert.assertEquals(L"1234567890", validationRule.getValid(L"", L"1234567890", errorList));
	Assert.assertEquals(0, errorList.size());
	Assert.assertEquals(null, validationRule.getValid(L"", L"123456789012345", errorList));
	Assert.assertEquals(1, errorList.size());
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestAllowNull) {

	StringValidationRule validationRule = new StringValidationRule(L"");

	Assert.assertFalse(validationRule.isAllowNull());
	Assert.assertFalse(validationRule.isValid(L"", null));

	validationRule.setAllowNull(true);
	Assert.assertTrue(validationRule.isAllowNull());
	Assert.assertTrue(validationRule.isValid(L"", null));
}*/

#endif // !defined(_GLIBCXX_DEBUG)
