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

#include "errors/FileNotFoundException.h"
using esapi::FileNotFoundException;

#include "errors/IllegalArgumentException.h"
using esapi::IllegalArgumentException;

#include "errors/ParseException.h"
using esapi::ParseException;

namespace esapi
{
  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_1Pa )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_1Nb )
  {
    bool success = false;
    try
      {
#if defined(ESAPI_OS_WINDOWS)
	PropertiesConfiguration config("C:\\wxyz\\qwerty\\ESAPI.properties");
#else    
	PropertiesConfiguration config("/wxyz/qwerty/ESAPI.properties");
#endif
      }
    catch(const FileNotFoundException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch FileNotFoundException");
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_4Na )
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
    catch(const IllegalArgumentException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch malformed key/value pair");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_4Nb )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Foo=1" << endl;
        ss << "Bar=2" << endl;
        ss << "Bah" << endl;
    
	PropertiesConfiguration config(ss);
      }
    catch(const IllegalArgumentException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch malformed key/value pair");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_5Na )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "=Foo" << endl;
        ss << "=Bar" << endl;
        ss << "=Bah" << endl;
    
	PropertiesConfiguration config(ss);
      }
    catch(const IllegalArgumentException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch malformed key/value pair");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_5Nb )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "XXX=Foo" << endl;
        ss << "YYY=Bar" << endl;
        ss << "=Bah" << endl;
    
	PropertiesConfiguration config(ss);
      }
    catch(const IllegalArgumentException& ex)
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

    BOOST_CHECK_MESSAGE(success, "Failed to catch malformed key/value pair");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pa )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pb )
  {
    try
      {
        stringstream ss;
        ss << " " << endl;
    
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pc )
  {
    try
      {
        stringstream ss;
        ss << "  \t\n\v\f\r" << endl;
    
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pd )
  {
    try
      {
        stringstream ss;
        ss << "  \b\b\b\b\b" << endl;
    
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pe )
  {
    try
      {
        stringstream ss;
        ss << "# Ignore this comment " << endl;
    
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pf )
  {
    try
      {
        stringstream ss;
        ss << "  # Ignore this comment too" << endl;
    
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_6Pg )
  {
    try
      {
        stringstream ss;
        ss << "\t\v\f\r\n# Ignore this one also" << endl;
    
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_9P )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_10N )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_11N )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_12P )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_13P )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_14N )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_15N )
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

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_16P )
  {
    String result;
    try
      {
        stringstream ss;
        ss << "Foo= " << endl;
    
	PropertiesConfiguration config(ss);
        result = config.getString("Foo");
      }
    catch(const std::exception& ex)
      {
	BOOST_ERROR(ex.what());
      }
    catch(...)
      {
	BOOST_ERROR("Caught unknown exception");
      }

    BOOST_CHECK_MESSAGE(result == "", "Failed to retrieve empty value");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_17P )
  {
    String result;
    try
      {
        stringstream ss;
        ss << "Foo=" << endl;
    
	PropertiesConfiguration config(ss);
        result = config.getString("Foo");
      }
    catch(const std::exception& ex)
      {
	BOOST_ERROR(ex.what());
      }
    catch(...)
      {
	BOOST_ERROR("Caught unknown exception");
      }

    BOOST_CHECK_MESSAGE(result == "", "Failed to retrieve empty value");
  }

  BOOST_AUTO_TEST_CASE( PropertiesConfiguration_18N )
  {
    bool success = false;
    try
      {
        stringstream ss;
        ss << "Bar=" << endl;
    
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

