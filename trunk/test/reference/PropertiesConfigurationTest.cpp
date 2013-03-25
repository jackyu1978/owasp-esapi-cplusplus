/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Jeffrey Walton, noloader@gmail.com
 * @author Kevin Wall, noloader@gmail.com
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

#include <sstream>
using std::stringstream;

#include "EsapiCommon.h"
using esapi::String;

#include "reference/PropertiesConfiguration.h"
using esapi::PropertiesConfiguration;

#include "errors/NoSuchPropertyException.h"
using esapi::NoSuchPropertyException;

#include "errors/ParseException.h"
using esapi::ParseException;

namespace esapi
{
  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_1P )
  {
    try
      {      
	PropertiesConfiguration config("");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_2P )
  {
    try
      {
        stringstream ss;
        ss << "Foo=Bar" << endl;
    
	PropertiesConfiguration config(ss);
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_3P )
  {
    try
      {
        stringstream ss;
        ss << "Foo=" << endl;
    
	PropertiesConfiguration config(ss);
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_4N )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Foo" << endl;
        ss << "Bar" << endl;
        ss << "Bah" << endl;
    
	PropertiesConfiguration config(ss);
      }
    catch(const std::exception& ex)
      {
	success = true;
      }
    catch(...)
      {
	BOOST_ERROR("Caught unknown exception");
      }

    BOOST_CHECK_MESSAGE(success, "Failed to catch something. What should we do???");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_5P )
  {
    try
      {
        stringstream ss;
        ss << endl << endl << endl;
    
	PropertiesConfiguration config(ss);
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6P )
  {
    try
      {
        stringstream ss;
        ss << "\tFoo\v = \fBar\r" << endl;
    
	PropertiesConfiguration config(ss);
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_7P )
  {
    try
      {
        stringstream ss;
        ss << "\tFoo\v = \fBar\r" << endl;
    
	PropertiesConfiguration config(ss);
        String result = config.getString("Foo");

        BOOST_CHECK_MESSAGE(result == "Bar", "Failed to retrieve value for key");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_8P )
  {
    try
      {
        stringstream ss;
        ss << "Bar=1" << endl;
        ss << "Bah=2" << endl;
    
	PropertiesConfiguration config(ss);

        String result = config.getString("Bar");
        BOOST_CHECK_MESSAGE(result == "1", "Failed to retrieve value for key");

        int n = config.getInt("Bah");
        BOOST_CHECK_MESSAGE(n == 2, "Failed to retrieve value for key");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_9N )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Foo=1" << endl;
    
	PropertiesConfiguration config(ss);
        String result = config.getString("Bar");
      }
    catch(const NoSuchPropertyException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch IllegalArgumentException");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_10N )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Foo=1" << endl;
    
	PropertiesConfiguration config(ss);
        int result = config.getInt("Bar");
      }
    catch(const NoSuchPropertyException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch IllegalArgumentException");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_11P )
  {
    try
      {
        stringstream ss;
        ss << "Foo=1" << endl;
        ss << "Foo=2" << endl;
    
	PropertiesConfiguration config(ss);

        String result = config.getString("Foo");
        BOOST_CHECK_MESSAGE(result == "1" || result == "2", "Failed to retrieve value for key");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_12P )
  {
    try
      {
        stringstream ss;
        ss << "Bar=1" << endl;
        ss << "Bar=2" << endl;
    
	PropertiesConfiguration config(ss);

        String result = config.getString("Bar");
        BOOST_CHECK_MESSAGE(result == "1" || result == "2", "Failed to retrieve value for key");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_13N )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Bar=wxyz" << endl;
    
	PropertiesConfiguration config(ss);
        int result = config.getInt("Bar");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_14N )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Bar=0xyz" << endl;
    
	PropertiesConfiguration config(ss);
        int result = config.getInt("Bar");
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

}   // namespace esapi

