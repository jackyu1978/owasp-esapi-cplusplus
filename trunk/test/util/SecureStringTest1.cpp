/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 */

#if defined(_WIN32)
    #if defined(STATIC_TEST)
        // do not enable BOOST_TEST_DYN_LINK
    #elif defined(DLL_TEST)
        #define BOOST_TEST_DYN_LINK
    #else
        #error "For Windows you must define either STATIC_TEST or DLL_TEST"
    #endif
#else
    #define BOOST_TEST_DYN_LINK
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
using esapi::StringStream;

#include <sstream>
using std::ostream;

#include <util/SecureString.h>
using esapi::SecureString;

static const Char THE_STRING[] = L"Goodbye, secret";
static const size_t THE_LENGTH = 15;

BOOST_AUTO_TEST_CASE( VerifyConstruction )
{
  bool success = false;

  try
    {
      success = false;

      SecureString ss;
      success = true;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to construct SecureString");

  try
    {
      success = false;

      SecureString ss(THE_STRING);
      success = (0 == ::memcmp(ss.c_str(), THE_STRING, ss.length()));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to construct SecureString");

  try
    {
      success = false;

      String s(THE_STRING);
      SecureString ss(s);
      success = (0 == ::memcmp(ss.c_str(), s.c_str(), ss.length()));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to construct SecureString");

  try
    {
      success = false;

      SecureString ss(THE_STRING, THE_LENGTH);
      success = ((ss.length() == THE_LENGTH) && (0 == ::memcmp(ss.c_str(), THE_STRING, THE_LENGTH)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to construct SecureString");

  try
    {
      success = false;

      SecureString ss1(THE_STRING);
      SecureString ss2(ss1);
      success = (0 == ::memcmp(ss1.c_str(), ss2.c_str(), ss1.length()));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to copy construct SecureString");

  try
    {
      success = false;

      SecureString ss(1, L'A');
      success = (0 == ::memcmp(ss.c_str(), L"A", 1));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to construct SecureString");

}

BOOST_AUTO_TEST_CASE( VerifyAssignment )
{
  bool success = false;

  try
    {
      success = false;

      SecureString ss = THE_STRING;
      success = ((ss.length() == THE_LENGTH) && (0 == ::memcmp(ss.c_str(), THE_STRING, THE_LENGTH)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to assign SecureString");

  try
    {
      success = false;

      SecureString ss;
      ss = THE_STRING;
      success = (0 == ::memcmp(ss.c_str(), THE_STRING, THE_LENGTH));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to assign SecureString");

  try
    {
      success = false;

      String s = THE_STRING;
      SecureString ss;
      ss = s;
      success = (0 == ::memcmp(ss.c_str(), s.c_str(), THE_LENGTH));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to assign SecureString");

  try
    {
      success = false;

      SecureString ss;
      ss = L'A';
      success = (0 == ::memcmp(ss.c_str(), L"A", 1));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, L"Failed to assign SecureString");
}


