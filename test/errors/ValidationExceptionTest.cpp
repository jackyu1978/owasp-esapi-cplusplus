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

#include <sstream>
using std::ostringstream;

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
    const std::string& ctx = exception.getContext();

    ostringstream oss;
    oss << "Failed to set context. Expected '" << context << "', ";
    oss << "got '" << ctx << "'.";

    BOOST_REQUIRE_MESSAGE( context == ctx, oss.str() );
}

BOOST_AUTO_TEST_CASE( test_try_catch )
{
    std::string umsg("user message"), lmsg("log message");
	try
    {
		throw esapi::ValidationException(umsg, lmsg);
		BOOST_FAIL("Expected exception was not thrown");
	}
    catch (const std::exception& ve)
    {
      ostringstream oss;
      oss << "Failed to pull exception message. Expected '" << umsg << "'";
      oss << ", got '" << ve.what() << "'.";

	  BOOST_CHECK_MESSAGE( ve.what() == umsg, oss.str() );
	}

	// BOOST_REQUIRE_THROW( throw new std::exception, std::exception );
	// BOOST_CHECK_THROW( throw new esapi::ValidationException("user message", "log message"), std::exception );
}

BOOST_AUTO_TEST_SUITE_END()
