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
#include "errors/IllegalArgumentException.h"
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


	try {
		validationRule.getValid(L"", L"Magnum44");
		BOOST_FAIL(L"Expected Exception not thrown");
	}
	catch (ValidationException& ve) {
		BOOST_CHECK(ve.getLogMessage().compare("")!=0); // should not be empty
	}


	try {
		BOOST_CHECK(validationRule.getValid(L"", L"MagnumPI").compare(L"MagnumPI")==0);
	} catch(ValidationException& ve) {
        NarrowString msg = NarrowString("Exception should not have been thrown: ") + ve.getLogMessage();
		BOOST_FAIL(msg);
	}

}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelistPattern_Invalid) {

	StringValidationRule validationRule(L"");

	//null white list patterns throw IllegalArgumentException
	try {
		String pattern = L"";
		validationRule.addWhitelistPattern(pattern);
		BOOST_FAIL("Expected Exception not thrown");
	} catch (IllegalArgumentException& ie) {
		BOOST_CHECK(!ie.getUserMessage().empty());
	}


	//invalid white list patterns throw PatternSyntaxException
	try {
		String pattern = L"_][0}[";
		validationRule.addWhitelistPattern(pattern);

		//validationRule.getValid(L"", L"test");

		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (std::exception &e) {
		BOOST_CHECK(e.what()!=0);
	}

}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelist){
	StringValidationRule validationRule(L"");

	std::set<Char> whitelistArray;
	whitelistArray.insert(L'a');
	whitelistArray.insert(L'b');
	whitelistArray.insert(L'c');

	BOOST_CHECK(validationRule.whitelist(L"12345abcdef", whitelistArray).compare(L"abc")==0);
}


BOOST_AUTO_TEST_CASE( StringValidationRuleTestBlacklistPattern) {

	StringValidationRule validationRule(L"NoAngleBrackets");

	BOOST_CHECK(validationRule.getValid(L"", L"beg <script> end").compare(L"beg <script> end")==0);

	validationRule.addBlacklistPattern(L"^.*(<|>).*");

	try {
		validationRule.getValid(L"", L"beg <script> end");
		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (ValidationException &ve) {
		BOOST_CHECK(!ve.getUserMessage().empty());
	}
	BOOST_CHECK(validationRule.getValid(L"", L"beg script end").compare(L"beg script end")==0);
}


BOOST_AUTO_TEST_CASE(StringValidationRuleTestBlacklistPattern_Invalid) {

	StringValidationRule validationRule(L"");

	//null black list patterns throw IllegalArgumentException
	try {
		String pattern = L"";
		validationRule.addBlacklistPattern(pattern);
		BOOST_FAIL(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException &ie) {
		BOOST_CHECK(!ie.getUserMessage().empty());
	}

	//invalid black list patterns throw PatternSyntaxException
	/*try {
		String pattern = "_][0}[";
		validationRule.addBlacklistPattern(pattern);
		Assert.fail(L"Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}*/
}
/*
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
