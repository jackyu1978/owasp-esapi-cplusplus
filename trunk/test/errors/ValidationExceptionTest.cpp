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

#include "util/TextConvert.h"
using esapi::TextConvert;

#include "errors/ValidationException.h"
using esapi::ValidationException;

BOOST_AUTO_TEST_SUITE( test_suite_ValidationException )

BOOST_AUTO_TEST_CASE( test_case_constructor_1 )
{
  ValidationException exception("user message", "log message");
}

BOOST_AUTO_TEST_CASE( test_case_constructor_2 )
{
  ValidationException exception(L"user message", L"log message");
}

BOOST_AUTO_TEST_CASE( test_case_setContext )
{
  String context = L"test context";
  ValidationException exception(L"user message", L"log message");
  exception.setContext(context);
  const String& ctx = exception.getContext();

  StringStream oss;
  oss << L"Failed to set context. Expected '" << context << L"', ";
  oss << L"got '" << ctx << L"'.";

  BOOST_REQUIRE_MESSAGE( context == ctx, TextConvert::WideToNarrow(oss.str()) );
}

BOOST_AUTO_TEST_CASE( test_try_catch )
{
  String umsg(L"user message"), lmsg(L"log message");
  try
    {
      throw ValidationException(umsg, lmsg);
      BOOST_FAIL("Expected exception was not thrown");
    }
  catch (const std::exception& ve)
    {
      StringStream oss;
      oss << L"Failed to pull exception message. Expected '" << umsg << L"'";
      oss << L", got '" << ve.what() << L"'.";

      BOOST_CHECK_MESSAGE( TextConvert::NarrowToWide(ve.what()) == umsg, TextConvert::WideToNarrow(oss.str()) );
    }

  // BOOST_REQUIRE_THROW( throw std::exception, std::exception );
  // BOOST_CHECK_THROW( throw ValidationException("user message", L"log message"), std::exception );
}

BOOST_AUTO_TEST_SUITE_END()

