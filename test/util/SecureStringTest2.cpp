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

#include <util/SecureString.h>
using esapi::SecureString;

void VerifyAppend();
void VerifyInsert();
void VerifyForwardFind();
void VerifyReverseFind();

BOOST_AUTO_TEST_CASE( VerifySecureString2 )
{
  BOOST_MESSAGE( "Verifying SecureString class (The Rest)" );

  VerifyAppend();
  VerifyInsert();
  VerifyForwardFind();
  VerifyReverseFind();
}

static const Char* THE_STRING1 = "Goodbye, secret";
static const Char* THE_STRING2 = "Foo Bar Bah";
static const Char* THE_STRING3 = "Goodbye, secretFoo Bar Bah";
static const Char* THE_STRING4 = "Goodbye, secretA";

void VerifyAppend()
{
  bool success = false;

  try
    {
      success = false;

      SecureString ss1 = THE_STRING1;
      SecureString ss2 = THE_STRING2;
      ss1 += ss2;
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING3, ::strlen(THE_STRING3)));
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
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING3, ::strlen(THE_STRING3)));
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
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING3, ::strlen(THE_STRING3)));
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
      success = (0 == ::memcmp(ss1.c_str(), THE_STRING4, ::strlen(THE_STRING4)));
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to append SecureString");
}

void VerifyInsert()
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

void VerifyForwardFind()
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

void VerifyReverseFind()
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


