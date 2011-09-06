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

#if !defined(ESAPI_OS_WINDOWS)
# define BOOST_TEST_DYN_LINK
# include <boost/test/unit_test.hpp>
using namespace boost::unit_test;
#endif

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <algorithm>
using std::equal;

#include <string>
using std::char_traits;
using std::basic_string;

#include <sstream>
using std::ostream;

#include <util/SecureArray.h>
using esapi::SecureByteArray;

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_1P )
{
  // Construction
  SecureByteArray vv;
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_2P )
{
  // Copy
  SecureByteArray vv;
  SecureByteArray ww(vv);
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_3P )
{
  // Assignment
  SecureByteArray vv;
  SecureByteArray ww = vv;
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_4N )
{
  bool success = false;
  try
  {
    const byte* ptr = NULL;
    SecureByteArray vv(ptr, 0);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on bad array");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_5P )
{
  bool success = true;
  try
  {
    const byte ptr[] = { 0 };
    SecureByteArray vv(ptr, 0);
    success &= (vv.size() == 0);
  }
  catch(std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to construct an empty array");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_6P )
{
  bool success = true;
  try
  {
    const byte ptr[] = { 0xFF };
    SecureByteArray vv(ptr, 0);
    success &= (vv.size() == 0);
    success &= (vv.data() == nullptr);
  }
  catch(std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to construct a single element array");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_7N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)(size_t)-4;
    SecureByteArray vv(ptr, 8);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect wrap");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_8N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)(size_t)-4;
    SecureByteArray vv;
    vv.assign(ptr, 8);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect assignment wrap");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_9N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)(size_t)-4;
    SecureByteArray vv;
    vv.insert(vv.begin(), ptr, 8);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_10N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)(size_t)-4;
    SecureByteArray vv;
    vv.insert(vv.end(), ptr, 8);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_11P )
{
  bool success = true;
  try
  {
    const byte ptr[] = { 2, 2, 2, 2 };
    SecureByteArray vv(4);
    vv.assign(ptr, COUNTOF(ptr));
    success &= (vv.size() == 4);
    success &= (::memcmp(vv.data(), ptr, 4) == 0);
  }
  catch(std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to assign array");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_12P )
{
  bool success = true;
  try
  {
    const byte ptr[] = { 2, 2 };
    SecureByteArray vv(2);
    vv.insert(vv.begin(), ptr, COUNTOF(ptr));
    success &= (vv.size() == 4);
    success &= (vv[0] == 2);
    success &= (vv[1] == 2);
    success &= (vv[2] == 0);
    success &= (vv[3] == 0);
  }
  catch(std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to insert array");
}

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_13P )
{
  bool success = true;
  try
  {
    const byte ptr[] = { 2, 2 };
    SecureByteArray vv(2);
    vv.insert(vv.end(), ptr, COUNTOF(ptr));
    success &= (vv.size() == 4);
    success &= (vv[0] == 0);
    success &= (vv[1] == 0);
    success &= (vv[2] == 2);
    success &= (vv[3] == 2);
  }
  catch(std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to insert array");
}

/*
BOOST_AUTO_TEST_CASE( SecureByteArrayTest_14N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)0x00000004;
    SecureByteArray vv;
    vv.assign(ptr, vv.max_size()+1);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect assignment wrap");
}
*/

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_15N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)0x00000004;
    SecureByteArray vv(16);
    vv.assign(ptr, vv.max_size()-1);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect assignment wrap");
}

/*
BOOST_AUTO_TEST_CASE( SecureByteArrayTest_16N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)0x00000004;
    SecureByteArray vv;
    vv.insert(vv.begin(), ptr, vv.max_size()+1);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}
*/

BOOST_AUTO_TEST_CASE( SecureByteArrayTest_17N )
{
  bool success = false;
  try
  {
    const byte* ptr = (const byte*)0x00000004;
    SecureByteArray vv(16);
    vv.insert(vv.begin(), ptr, vv.max_size()-1);
  }
  catch(std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}
