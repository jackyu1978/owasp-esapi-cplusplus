/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2013 - The OWASP Foundation
 *
 * @author Jeffrey Walton, dan.amodio@aspectsecurity.com
 *
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
using esapi::String;

#include "reference/Configuration.h"
using esapi::Configuration;

#include "errors/ParseException.h"
using esapi::ParseException;

BOOST_AUTO_TEST_CASE( Configuration_2_1P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseInt("0");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '0'");
      result = config.parseInt(" 0 ");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse ' 0 '");
      result = config.parseInt("0\n");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '0\\n'");
      result = config.parseInt("\t0");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '\\t0'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_2P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseInt("1");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '1'");
      result = config.parseInt(" 1 ");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse ' 1 '");
      result = config.parseInt("1\n");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '1\\n'");
      result = config.parseInt("\t1");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '\\t1'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_3P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseInt("-1");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '-1'");
      result = config.parseInt(" -1 ");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse ' -1 '");
      result = config.parseInt("-1\n");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '-1\\n'");
      result = config.parseInt("\t-1");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '\\t-1'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_4P )
{
  try
    {
      Configuration config;
      int result; 
      
      result = config.parseInt("-2147483648");
      BOOST_CHECK_MESSAGE(result == -2147483648, "Failed to parse '-2147483648'");
      result = config.parseInt(" -2147483648 ");
      BOOST_CHECK_MESSAGE(result == -2147483648, "Failed to parse ' -2147483648 '");
      result = config.parseInt("-2147483648\n");
      BOOST_CHECK_MESSAGE(result == -2147483648, "Failed to parse '-2147483648\\n'");
      result = config.parseInt("\t-2147483648");
      BOOST_CHECK_MESSAGE(result == -2147483648, "Failed to parse '\\t-2147483648'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_5P )
{
  try
    {
      Configuration config;
      int result; 
      
      result = config.parseInt("2147483647");
      BOOST_CHECK_MESSAGE(result == 2147483647, "Failed to parse '2147483647'");
      result = config.parseInt(" 2147483647 ");
      BOOST_CHECK_MESSAGE(result == 2147483647, "Failed to parse ' 2147483647 '");
      result = config.parseInt("2147483647\n");
      BOOST_CHECK_MESSAGE(result == 2147483647, "Failed to parse '2147483647\\n'");
      result = config.parseInt("\t2147483647");
      BOOST_CHECK_MESSAGE(result == 2147483647, "Failed to parse '\\t2147483647'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_6P )
{
  try
    {
      Configuration config;
      int result; 
      
      result = config.parseInt("0x01");
      BOOST_CHECK_MESSAGE(result == 0x01, "Failed to parse '0x01'");
      result = config.parseInt(" 0x01 ");
      BOOST_CHECK_MESSAGE(result == 0x01, "Failed to parse ' 0x01 '");
      result = config.parseInt("0x01\n");
      BOOST_CHECK_MESSAGE(result == 0x01, "Failed to parse '0x01\\n'");
      result = config.parseInt("\t0x01");
      BOOST_CHECK_MESSAGE(result == 0x01, "Failed to parse '\\t0x01'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_7P )
{
  try
    {
      Configuration config;
      int result; 
      
      result = config.parseInt("0x00");
      BOOST_CHECK_MESSAGE(result == 0x00, "Failed to parse '0x00'");
      result = config.parseInt(" 0x00 ");
      BOOST_CHECK_MESSAGE(result == 0x00, "Failed to parse ' 0x00 '");
      result = config.parseInt("0x00\n");
      BOOST_CHECK_MESSAGE(result == 0x00, "Failed to parse '0x00\\n'");
      result = config.parseInt("\t0x00");
      BOOST_CHECK_MESSAGE(result == 0x00, "Failed to parse '\\t0x00'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_8P )
{
  try
    {
      Configuration config;
      int result; 
      
      result = config.parseInt("0xFFFFFFFF");
      BOOST_CHECK_MESSAGE(result == (int)0xFFFFFFFF, "Failed to parse '0xFFFFFFFF'");
      result = config.parseInt(" 0xFFFFFFFF ");
      BOOST_CHECK_MESSAGE(result == (int)0xFFFFFFFF, "Failed to parse ' 0xFFFFFFFF '");
      result = config.parseInt("0xFFFFFFFF\n");
      BOOST_CHECK_MESSAGE(result == (int)0xFFFFFFFF, "Failed to parse '0xFFFFFFFF\\n'");
      result = config.parseInt("\t0xFFFFFFFF");
      BOOST_CHECK_MESSAGE(result == (int)0xFFFFFFFF, "Failed to parse '\\t0xFFFFFFFF'");
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( Configuration_2_9N )
{
  Configuration config;
  int result;
  bool success;

  try
    {
      success = false;
      result = config.parseInt("");
    }
  catch(const ParseException& ex)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

    BOOST_CHECK_MESSAGE(success, "Failed to catch ParseException");
}

BOOST_AUTO_TEST_CASE( Configuration_2_10N )
{
  Configuration config;
  int result;
  bool success;

  try
    {
      success = false;
      result = config.parseInt("xxx");
    }
  catch(const ParseException& ex)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

    BOOST_CHECK_MESSAGE(success, "Failed to catch ParseException");
}

BOOST_AUTO_TEST_CASE( Configuration_2_11N )
{
  Configuration config;
  int result;
  bool success;

  try
    {
      success = false;
      result = config.parseInt("#-#");
    }
  catch(const ParseException& ex)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

    BOOST_CHECK_MESSAGE(success, "Failed to catch ParseException");
}

BOOST_AUTO_TEST_CASE( Configuration_2_12N )
{
  Configuration config;
  int result;
  bool success;

  try
    {
      success = false;
      result = config.parseInt("0x");
    }
  catch(const ParseException& ex)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

    BOOST_CHECK_MESSAGE(success, "Failed to catch ParseException");
}

BOOST_AUTO_TEST_CASE( Configuration_2_13N )
{
  Configuration config;
  int result;
  bool success;

  try
    {
      success = false;
      result = config.parseInt("0xFFFFFFFFFFFFFFFF");
    }
  catch(const ParseException& ex)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

    BOOST_CHECK_MESSAGE(success, "Failed to catch ParseException");
}

