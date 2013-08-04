/*
 * ValidationExceptionTest.cpp
 *
 *  Created on: Aug 8, 2011
 *      Author: David Anderson
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
using esapi::NarrowString;
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
  ValidationException exception("user message", "log message");
}

BOOST_AUTO_TEST_CASE( test_case_setContext )
{
  NarrowString context = "test context";
  ValidationException exception("user message", "log message");
  exception.setContext(context);
  const NarrowString& ctx = exception.getContext();

  StringStream oss;
  oss << "Failed to set context. Expected '" << context << "', ";
  oss << "got '" << ctx << "'.";

  BOOST_REQUIRE_MESSAGE( context == ctx, oss.str() );
}

BOOST_AUTO_TEST_CASE( test_try_catch )
{
  NarrowString umsg("user message"), lmsg("log message");
  try
    {
      throw ValidationException(umsg, lmsg);
      BOOST_FAIL("Expected exception was not thrown");
    }
  catch (const std::exception& ve)
    {
      StringStream oss;
      oss << "Failed to pull exception message. Expected '" << umsg << "'";
      oss << ", got '" << ve.what() << "'.";

      BOOST_CHECK_MESSAGE(ve.what() == umsg, oss.str());
    }

  // BOOST_REQUIRE_THROW( throw std::exception, std::exception );
  // BOOST_CHECK_THROW( throw ValidationException("user message", "log message"), std::exception );
}

BOOST_AUTO_TEST_SUITE_END()

