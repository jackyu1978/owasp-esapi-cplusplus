/*
 * ValidationExceptionTest.cpp
 *
 *  Created on: Aug 8, 2011
 *      Author: David Anderson
 */

#define BOOST_TEST_DYN_LINK
#include "boost/test/unit_test.hpp"
#include "errors/ValidationException.h"
#include <exception>

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

BOOST_AUTO_TEST_CASE( test_try_catch )
{
	/*try {
		throw new esapi::ValidationException("user message", "log message");
		BOOST_FAIL("Expected exception was not thrown");
	} catch (std::exception& ve) {
		BOOST_CHECK(ve.what()=="user message");
	}*/

	try{
		throw new std::exception;
	} catch (std::exception& e) {
		//do nothing;
	}

	//BOOST_REQUIRE_THROW( throw new std::exception, std::exception );
	//BOOST_CHECK_THROW( throw new esapi::ValidationException("user message", "log message"), std::exception );
}

BOOST_AUTO_TEST_SUITE_END()
