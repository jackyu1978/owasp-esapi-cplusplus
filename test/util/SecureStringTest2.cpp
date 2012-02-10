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

#include <util/SecureString.h>
using esapi::SecureString;

static const Char THE_STRING1[] = L"Goodbye, secret";
static const Char THE_STRING2[] = L"Foo Bar Bah";
static const Char THE_STRING3[] = L"Goodbye, secretFoo Bar Bah";
static const Char THE_STRING4[] = L"Goodbye, secretA";

BOOST_AUTO_TEST_CASE( VerifyAppend )
{
  bool success = false;

  try
    {
      success = false;

      SecureString ss1 = THE_STRING1;
      SecureString ss2 = THE_STRING2;
      ss1 += ss2;
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING3, COUNTOF(THE_STRING3)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to append SecureString");

  try
    {
      success = false;

      SecureString ss1 = THE_STRING1;
      String ss2 = THE_STRING2;
      ss1 += ss2;
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING3, COUNTOF(THE_STRING3)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to append SecureString");

  try
    {
      success = false;

      SecureString ss1 = THE_STRING1;
      ss1 += THE_STRING2;
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING3, COUNTOF(THE_STRING3)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to append SecureString");

  try
    {
      success = false;

      SecureString ss1 = THE_STRING1;
      ss1 += L'A';
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING4, COUNTOF(THE_STRING4)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to append SecureString");
}

BOOST_AUTO_TEST_CASE( VerifyInsert )
{
  bool success = false;

  try
    {
      String s1 = THE_STRING1;
      SecureString ss1 = THE_STRING1;

      s1.insert(4, THE_STRING1);
      ss1.insert(4, THE_STRING1);

      success = (s1 == ss1);
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to insert SecureString");
}

BOOST_AUTO_TEST_CASE( VerifyForwardFind )
{
  bool success = false;

  try
    {
      String s1 = THE_STRING1;
      String::size_type sp = s1.find(L"s");

      SecureString ss1 = THE_STRING1;
      SecureString::size_type ssp = s1.find(L"s");

      success = (sp == ssp);
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to find SecureString");

  try
    {
      String s1 = THE_STRING1;
      String::size_type sp = s1.find(L"z");

      SecureString ss1 = THE_STRING1;
      SecureString::size_type ssp = s1.find(L"z");

      success = (sp == ssp);
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to find SecureString");
}

BOOST_AUTO_TEST_CASE( VerifyReverseFind )
{
  bool success = false;

  try
    {
      String s1 = THE_STRING1;
      String::size_type sp = s1.rfind(L"s");

      SecureString ss1 = THE_STRING1;
      SecureString::size_type ssp = s1.rfind(L"s");

      success = (sp == ssp);
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to rfind SecureString");

  try
    {
      String s1 = THE_STRING1;
      String::size_type sp = s1.rfind(L"z");

      SecureString ss1 = THE_STRING1;
      SecureString::size_type ssp = s1.rfind(L"z");

      success = (sp == ssp);
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to rfind SecureString");
}


