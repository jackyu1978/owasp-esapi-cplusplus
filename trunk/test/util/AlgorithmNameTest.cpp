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

#include "EsapiCommon.h"
using esapi::NarrowString;
using esapi::WideString;

#include <util/AlgorithmName.h>
using esapi::AlgorithmName;

#include "errors/NoSuchAlgorithmException.h"
using esapi::NoSuchAlgorithmException;

BOOST_AUTO_TEST_CASE( AlgorithmName_1P )
{
  // Construction
  NarrowString s("DES/ECB/NoPadding");
  AlgorithmName a(s);
}

BOOST_AUTO_TEST_CASE( AlgorithmName_2P )
{
  // Copy
  NarrowString s("DES/ECB/NoPadding");
  AlgorithmName a(s);
  AlgorithmName aa(a);
}

BOOST_AUTO_TEST_CASE( AlgorithmName_3P )
{
  // Assignment
  NarrowString s("DES/ECB/NoPadding");
  AlgorithmName a(s);
  AlgorithmName aa = a;
}

BOOST_AUTO_TEST_CASE( AlgorithmName_4P )
{
  // Construction
  WideString s(L"DES/ECB/NoPadding");
  AlgorithmName a(s);
}

BOOST_AUTO_TEST_CASE( AlgorithmName_5P )
{
  // Copy
  WideString s(L"DES/ECB/NoPadding");
  AlgorithmName a(s);
  AlgorithmName aa(a);
}

BOOST_AUTO_TEST_CASE( AlgorithmName_6P )
{
  // Assignment
  WideString s(L"DES/ECB/NoPadding");
  AlgorithmName a(s);
  AlgorithmName aa = a;
}

BOOST_AUTO_TEST_CASE( AlgorithmName_7P )
{
  AlgorithmName aa("AES");
  
  NarrowString alg;
  aa.getCipher(alg);

  BOOST_CHECK_MESSAGE(alg == "AES", "Failed to getCipher (1)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_8P )
{
  AlgorithmName aa(L"AES");
  
  WideString alg;
  aa.getCipher(alg);

  BOOST_CHECK_MESSAGE(alg == L"AES", "Failed to getCipher (2)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_9P )
{
  AlgorithmName aa("AES/CBC/PKCS5Padding");
  
  NarrowString alg;
  aa.getCipher(alg);

  BOOST_CHECK_MESSAGE(alg == "AES", "Failed to getCipher (3)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_10P )
{
  AlgorithmName aa(L"AES/CBC/PKCS5Padding");
  
  WideString alg;
  aa.getCipher(alg);

  BOOST_CHECK_MESSAGE(alg == L"AES", "Failed to getCipher (4)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_11P )
{
  AlgorithmName aa("AES/CBC/PKCS5Padding");
  
  NarrowString mode;
  aa.getMode(mode);

  BOOST_CHECK_MESSAGE(mode == "CBC", "Failed to getMode (1)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_12P )
{
  AlgorithmName aa(L"AES/CBC/PKCS5Padding");
  
  WideString mode;
  aa.getMode(mode);

  BOOST_CHECK_MESSAGE(mode == L"CBC", "Failed to getMode (2)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_13P )
{
  AlgorithmName aa("AES/CBC/PKCS5Padding");
  
  NarrowString padding;
  aa.getPadding(padding);

  BOOST_CHECK_MESSAGE(padding == "PKCS5Padding", "Failed to getPadding (1)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_14P )
{
  AlgorithmName aa(L"AES/CBC/PKCS5Padding");
  
  WideString padding;
  aa.getPadding(padding);

  BOOST_CHECK_MESSAGE(padding == L"PKCS5Padding", "Failed to getPadding (2)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_15P )
{
  AlgorithmName aa("AES/CBC/PKCS5Padding");  
  NarrowString alg = aa.algorithm();

  BOOST_CHECK_MESSAGE(alg == "AES/CBC/PKCS5Padding", "Failed to algorithm (1)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_16P )
{
  AlgorithmName aa(L"AES/CBC/PKCS5Padding");
  NarrowString alg = aa.algorithm();

  BOOST_CHECK_MESSAGE(alg == "AES/CBC/PKCS5Padding", "Failed to algorithm (2)");
}

BOOST_AUTO_TEST_CASE( AlgorithmName_100N )
{
  try
    {
      AlgorithmName aa("Foo");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus algorithm (1)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_101N )
{
  try
    {
      AlgorithmName aa("Foo/CBC/PKCS5Padding");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus cipher in algorithm (2)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_102N )
{
  try
    {
      AlgorithmName aa("AES/Foo/PKCS5Padding");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus mode in algorithm (3)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_103N )
{
  try
    {
      AlgorithmName aa("AES/CBC/Foo");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus padding in algorithm (4)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_104N )
{
  try
    {
      AlgorithmName aa("AES/CBC/PKCS5Padding/Foo");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus data in algorithm (5)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_105N )
{
  try
    {
      AlgorithmName aa("AES/CBC/PKCS5Padding/Foo/Bar");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus data in algorithm (6)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_106N )
{
  try
    {
      AlgorithmName aa("AES/CBC/PKCS5Padding/Foo/Bar/Bah");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch bogus data in algorithm (7)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_107N )
{
  try
    {
      AlgorithmName aa("/CBC/PKCS5Padding");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing cipher in algorithm (8)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_108N )
{
  try
    {
      AlgorithmName aa("AES//PKCS5Padding");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing mode in algorithm (9)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

#if 0
BOOST_AUTO_TEST_CASE( AlgorithmName_109N )
{
  try
    {
      AlgorithmName aa("AES/CBC/");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing padding in algorithm (10)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}
#endif

BOOST_AUTO_TEST_CASE( AlgorithmName_110N )
{
  try
    {
      AlgorithmName aa("/");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing cipher/padding in algorithm (11)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_111N )
{
  try
    {
      AlgorithmName aa("//");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing cipher/padding/mode in algorithm (12)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE( AlgorithmName_112N )
{
  try
    {
      AlgorithmName aa("//PKCS5Padding");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing cipher/padding in algorithm (13)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

#if 0
BOOST_AUTO_TEST_CASE( AlgorithmName_113N )
{
  try
    {
      AlgorithmName aa("AES/CBC/PKCS5Padding/");  
      NarrowString alg = aa.algorithm();

      BOOST_ERROR("Failed to catch missing cipher/padding in algorithm (14)");
    }
  catch(const NoSuchAlgorithmException&)
    {
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}
#endif

