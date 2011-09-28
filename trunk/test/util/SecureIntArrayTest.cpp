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

#include <sstream>
using std::ostream;

#include <util/SecureArray.h>
using esapi::SecureIntArray;

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_1P )
{
  // Construction
  SecureIntArray vv;
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_2P )
{
  // Copy
  SecureIntArray vv;
  SecureIntArray ww(vv);

  BOOST_CHECK_MESSAGE(ww.size() == 0, "Failed to copy SecureIntArray");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_3P )
{
  // Copy
  SecureIntArray vv(10);
  SecureIntArray ww(vv);

  BOOST_CHECK_MESSAGE(ww.size() == 10, "Failed to copy SecureIntArray");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_4P )
{
  // Assignment
  SecureIntArray vv;
  SecureIntArray ww = vv;

  BOOST_CHECK_MESSAGE(ww.size() == 0, "Failed to copy SecureIntArray");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_5P )
{
  // Assignment
  SecureIntArray vv(10);
  SecureIntArray ww = vv;

  BOOST_CHECK_MESSAGE(ww.size() == 10, "Failed to copy SecureIntArray");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_6P )
{
  bool success = true;
  SecureIntArray vv(4);

  try
  {
    const int arr[] = { 2, 2, 2, 2 };    
    vv.assign(arr, COUNTOF(arr));

    success &= (vv.size() == 4);
    success &= (::memcmp(vv.data(), arr, sizeof(arr)) == 0);
  }
  catch(const std::exception&)
  {
    success = false;
  }

  std::ostringstream oss;
  oss << "Failed to insert array. Expected { 2,2,2,2 }, got { ";
  for(size_t i = 0; i < vv.size(); i++)
    oss << vv[i] << " ";
  oss << "}";
  
  BOOST_CHECK_MESSAGE(success, oss.str());
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_7P )
{
  bool success = true;
  SecureIntArray vv(2);

  try
  {
    const int ptr[] = { 2, 2 };    
    vv.insert(vv.begin(), ptr, COUNTOF(ptr));

    success &= (vv.size() == 4);
    success &= (vv[0] == 2);
    success &= (vv[1] == 2);
    success &= (vv[2] == 0);
    success &= (vv[3] == 0);
  }
  catch(const std::exception&)
  {
    success = false;
  }

  std::ostringstream oss;
  oss << "Failed to insert array. Expected { 2,2,0,0 }, got { ";
  for(size_t i = 0; i < vv.size(); i++)
    oss << vv[i] << " ";
  oss << "}";
  
  BOOST_CHECK_MESSAGE(success, oss.str());
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_8P )
{
  bool success = true;
  SecureIntArray vv(2);

  try
  {
    const int ptr[] = { 2, 2 };
    vv.insert(vv.end(), ptr, COUNTOF(ptr));

    success &= (vv.size() == 4);
    success &= (vv[0] == 0);
    success &= (vv[1] == 0);
    success &= (vv[2] == 2);
    success &= (vv[3] == 2);
  }
  catch(const std::exception&)
  {
    success = false;
  }

  std::ostringstream oss;
  oss << "Failed to insert array. Expected { 0,0,2,2 }, got { ";
  for(size_t i = 0; i < vv.size(); i++)
    oss << vv[i] << " ";
  oss << "}";
  
  BOOST_CHECK_MESSAGE(success, oss.str());
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_9N )
{
  bool success = false;
  try
  {
    const int* ptr = NULL;
    SecureIntArray vv(ptr, 0);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on bad array");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_10P )
{
  bool success = true;
  try
  {
    const int ptr[] = { 0 };
    SecureIntArray vv(ptr, 0);
    success &= (vv.size() == 0);
  }
  catch(const std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to construct an empty array");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_11P )
{
  bool success = true;
  try
  {
    const int ptr[] = { 0xFFFFFFFF };
    SecureIntArray vv(ptr, 0);
    success &= (vv.size() == 0);
    success &= (vv.data() == nullptr);
  }
  catch(const std::exception&)
  {
    success = false;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to construct a single element array");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_12N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)((size_t)0 - sizeof(int));
    SecureIntArray vv(ptr, 8);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect wrap");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_13N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)((size_t)0 - sizeof(int));
    SecureIntArray vv;
    vv.assign(ptr, 8);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect assignment wrap");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_14N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)((size_t)0 - sizeof(int));
    SecureIntArray vv;
    vv.insert(vv.begin(), ptr, 8);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_15N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)((size_t)0 - sizeof(int));
    SecureIntArray vv;
    vv.insert(vv.end(), ptr, 8);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_16N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)sizeof(int);
    SecureIntArray vv;
    vv.assign(ptr, vv.max_size()+1);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect assignment wrap");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_17N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)sizeof(int);
    SecureIntArray vv;
    vv.insert(vv.begin(), ptr, vv.max_size()+1);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}

BOOST_AUTO_TEST_CASE( SecureIntArrayTest_18N )
{
  bool success = false;
  try
  {
    const int* ptr = (const int*)sizeof(int);
    SecureIntArray vv(16);
    vv.insert(vv.begin(), ptr, vv.max_size()-1);
  }
  catch(const std::exception&)
  {
    success = true;
  }
  BOOST_CHECK_MESSAGE(success, "Failed to detect insertion wrap");
}

