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

#include "EsapiCommon.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <map>
#include <set>
#include <exception>

#include <boost/regex.hpp>

#include <sstream>
using std::stringstream;
using std::istringstream;
using std::ostringstream;

#include "reference/validation/StringValidationRule.h"
#include "errors/ValidationException.h"
using namespace esapi;

BOOST_AUTO_TEST_CASE( BoostRegexTest) {
	const boost::regex re("^[a-zA-Z]*");
	BOOST_CHECK(boost::regex_match("asdf",re));
	BOOST_CHECK(!boost::regex_match("234SDFG",re));
}

BOOST_AUTO_TEST_CASE( StringValidationRuleTestWhitelistPattern) {

	StringValidationRule validationRule("Alphabetic");
	validationRule.validateInputAndCanonical = false;

	BOOST_CHECK(validationRule.checkEmpty("", "asdf").compare("asdf")==0);

	BOOST_CHECK(validationRule.checkLength("", "asdf").compare("asdf")==0);

	BOOST_CHECK(validationRule.checkWhitelist("", "asdf").compare("asdf")==0);

	BOOST_CHECK(validationRule.checkBlacklist("", "asdf").compare("asdf")==0);

	try {
		BOOST_CHECK(validationRule.getValid("", "asdf").compare("asdf")==0);
	} catch(ValidationException& ve) {
		BOOST_FAIL("Exception should not have been thrown: " + ve.getLogMessage());
	}


	validationRule.addWhitelistPattern("^[a-zA-Z]*");

	/*
	try {
		validationRule.getValid("", "Magnum44");
		BOOST_FAIL("Expected Exception not thrown");
	}
	catch (ValidationException& ve) {
		BOOST_CHECK(!ve.getContext().empty()); // should not be empty
	}*/


	try {
		BOOST_CHECK(validationRule.getValid("", "MagnumPI").compare("MagnumPI")==0);
	} catch(ValidationException& ve) {
		BOOST_FAIL("Exception should not have been thrown: " + ve.getLogMessage());
	}

}
/*
BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelistPattern_Invalid) {

	StringValidationRule validationRule = new StringValidationRule("");

	//null white list patterns throw IllegalArgumentException
	try {
		String pattern = null;
		validationRule.addWhitelistPattern(pattern);
		Assert.fail("Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	try {
		java.util.regex.Pattern pattern = null;
		validationRule.addWhitelistPattern(pattern);
		Assert.fail("Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	//invalid white list patterns throw PatternSyntaxException
	try {
		String pattern = "_][0}[";
		validationRule.addWhitelistPattern(pattern);
		Assert.fail("Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestWhitelist){
	StringValidationRule validationRule = new StringValidationRule("");

	char[] whitelistArray = new char[] {'a', 'b', 'c'};
	Assert.assertEquals("abc", validationRule.whitelist("12345abcdef", whitelistArray));
}

BOOST_AUTO_TEST_CASE( StringValidationRuleTestBlacklistPattern) {

	StringValidationRule validationRule = new StringValidationRule("NoAngleBrackets");

	Assert.assertEquals("beg <script> end", validationRule.getValid("", "beg <script> end"));
	validationRule.addBlacklistPattern("^.*(<|>).*");
	try {
		validationRule.getValid("", "beg <script> end");
		Assert.fail("Expected Exception not thrown");
	}
	catch (ValidationException ve) {
		Assert.assertNotNull(ve.getMessage());
	}
	Assert.assertEquals("beg script end", validationRule.getValid("", "beg script end"));
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestBlacklistPattern_Invalid) {

	StringValidationRule validationRule = new StringValidationRule("");

	//null black list patterns throw IllegalArgumentException
	try {
		String pattern = null;
		validationRule.addBlacklistPattern(pattern);
		Assert.fail("Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	try {
		java.util.regex.Pattern pattern = null;
		validationRule.addBlacklistPattern(pattern);
		Assert.fail("Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}

	//invalid black list patterns throw PatternSyntaxException
	try {
		String pattern = "_][0}[";
		validationRule.addBlacklistPattern(pattern);
		Assert.fail("Expected Exception not thrown");
	}
	catch (IllegalArgumentException ie) {
		Assert.assertNotNull(ie.getMessage());
	}
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestCheckLengths) {

	StringValidationRule validationRule = new StringValidationRule("Max12_Min2");
	validationRule.setMinimumLength(2);
	validationRule.setMaximumLength(12);

	Assert.assertTrue(validationRule.isValid("", "12"));
	Assert.assertTrue(validationRule.isValid("", "123456"));
	Assert.assertTrue(validationRule.isValid("", "ABCDEFGHIJKL"));

	Assert.assertFalse(validationRule.isValid("", "1"));
	Assert.assertFalse(validationRule.isValid("", "ABCDEFGHIJKLM"));

	ValidationErrorList errorList = new ValidationErrorList();
	Assert.assertEquals("1234567890", validationRule.getValid("", "1234567890", errorList));
	Assert.assertEquals(0, errorList.size());
	Assert.assertEquals(null, validationRule.getValid("", "123456789012345", errorList));
	Assert.assertEquals(1, errorList.size());
}

BOOST_AUTO_TEST_CASE(StringValidationRuleTestAllowNull) {

	StringValidationRule validationRule = new StringValidationRule("");

	Assert.assertFalse(validationRule.isAllowNull());
	Assert.assertFalse(validationRule.isValid("", null));

	validationRule.setAllowNull(true);
	Assert.assertTrue(validationRule.isAllowNull());
	Assert.assertTrue(validationRule.isValid("", null));
}*/
