/*
 * ValidationExceptionTest.cpp
 *
 *  Created on: Aug 8, 2011
 *      Author: David Anderson
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
using esapi::StringStream;

#include "errors/ValidationException.h"
using esapi::ValidationException;

BOOST_AUTO_TEST_SUITE( test_suite_ValidationException )

BOOST_AUTO_TEST_CASE( test_case_constructor )
{
  ValidationException exception(L"user message", "log message");
}

BOOST_AUTO_TEST_CASE( test_case_setContext )
{
  String context = "test context";
  ValidationException exception(L"user message", "log message");
  exception.setContext(context);
  const String& ctx = exception.getContext();

  StringStream oss;
  oss << "Failed to set context. Expected '" << context << "', ";
  oss << "got '" << ctx << "'.";

  BOOST_REQUIRE_MESSAGE( context == ctx, oss.str() );
}

BOOST_AUTO_TEST_CASE( test_try_catch )
{
  String umsg(L"user message"), lmsg(L"log message");
  try
    {
      throw ValidationException(umsg, lmsg);
      BOOST_FAIL(L"Expected exception was not thrown");
    }
  catch (const std::exception& ve)
    {
      StringStream oss;
      oss << "Failed to pull exception message. Expected '" << umsg << "'";
      oss << ", got '" << ve.what() << "'.";

      BOOST_CHECK_MESSAGE( ve.what() == umsg, oss.str() );
    }

  // BOOST_REQUIRE_THROW( throw new std::exception, std::exception );
  // BOOST_CHECK_THROW( throw new ValidationException(L"user message", "log message"), std::exception );
}

BOOST_AUTO_TEST_SUITE_END()

