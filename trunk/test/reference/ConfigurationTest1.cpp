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

BOOST_AUTO_TEST_CASE( Configuration_1_1P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("0");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '0'");
      result = config.parseBool(" 0 ");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse ' 0 '");
      result = config.parseBool("0\n");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '0\\n'");
      result = config.parseBool("\t0");
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

BOOST_AUTO_TEST_CASE( Configuration_1_2P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("false");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse 'false'");
      result = config.parseBool(" false ");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse ' false '");
      result = config.parseBool("false\n");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse 'false\\n'");
      result = config.parseBool("\tfalse");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '\\tfalse'");
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

BOOST_AUTO_TEST_CASE( Configuration_1_3P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("off");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse 'off'");
      result = config.parseBool(" off ");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse ' off '");
      result = config.parseBool("off\n");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse 'off\\n'");
      result = config.parseBool("\toff");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '\\toff'");
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

BOOST_AUTO_TEST_CASE( Configuration_1_4P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("no");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse 'no'");
      result = config.parseBool(" no ");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse ' no '");
      result = config.parseBool("no\n");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse 'no\\n'");
      result = config.parseBool("\tno");
      BOOST_CHECK_MESSAGE(result == false, "Failed to parse '\\tno'");
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

BOOST_AUTO_TEST_CASE( Configuration_1_5P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("1");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '1'");
      result = config.parseBool(" 1 ");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse ' 1 '");
      result = config.parseBool("1\n");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '1\\n'");
      result = config.parseBool("\t1");
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

BOOST_AUTO_TEST_CASE( Configuration_1_6P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("true");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse 'true'");
      result = config.parseBool(" true ");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse ' true '");
      result = config.parseBool("true\n");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse 'true\\n'");
      result = config.parseBool("\ttrue");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '\\ttrue'");
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

BOOST_AUTO_TEST_CASE( Configuration_1_7P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("on");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse 'on'");
      result = config.parseBool(" on ");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse ' on '");
      result = config.parseBool("on\n");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse 'on\\n'");
      result = config.parseBool("\ton");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '\\ton'");
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

BOOST_AUTO_TEST_CASE( Configuration_1_8P )
{
  try
    {
      Configuration config;
      bool result; 
      
      result = config.parseBool("yes");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse 'yes'");
      result = config.parseBool(" yes ");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse ' yes '");
      result = config.parseBool("yes\n");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse 'yes\\n'");
      result = config.parseBool("\tyes");
      BOOST_CHECK_MESSAGE(result == true, "Failed to parse '\\tyes'");
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

BOOST_AUTO_TEST_CASE( Configuration_1_9N )
{
  Configuration config;
  bool result, success;

  try
    {
      success = false;
      result = config.parseBool("");
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

  BOOST_CHECK_MESSAGE(success, "Failed to catch ParseException for empty string");
}

BOOST_AUTO_TEST_CASE( Configuration_1_10N )
{
  Configuration config;
  bool result, success;

  try
    {
      success = false;
      result = config.parseBool("xxx");
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

BOOST_AUTO_TEST_CASE( Configuration_1_11N )
{
  Configuration config;
  bool result, success;

  try
    {
      success = false;
      result = config.parseBool("#-#");
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

BOOST_AUTO_TEST_CASE( Configuration_1_12N )
{
  Configuration config;
  bool result, success;

  try
    {
      success = false;
      result = config.parseBool("0x");
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

