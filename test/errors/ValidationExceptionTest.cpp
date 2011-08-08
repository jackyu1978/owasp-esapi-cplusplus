/*
 * ValidationExceptionTest.cpp
 *
 *  Created on: Aug 8, 2011
 *      Author: David Anderson
 */

#define BOOST_TEST_DYN_LINK
#include "boost/test/unit_test.hpp"
#include "errors/ValidationException.h"

BOOST_AUTO_TEST_SUITE( test_suite_ValidationException )

BOOST_AUTO_TEST_CASE( test_case_constructor )
{
	esapi::ValidationException exception("user message", "log message");
}

BOOST_AUTO_TEST_CASE( test_case_setContext )
{
	std::string context = "test context";
	esapi::ValidationException exception("user message", "log message");
	exception.setContext(context);
    BOOST_REQUIRE( context == exception.getContext() );
}

BOOST_AUTO_TEST_SUITE_END()
