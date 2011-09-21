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
 * @author David Anderson, david.anderson@aspectsecurity.com
 */

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"

#include <string>
using String;

#include <cstdlib>
#include <cstring>

#include <crypto/CryptoHelper.h>
using esapi::CryptoHelper;
using esapi::SecretKey;

//BOOST_AUTO_TEST_CASE( VerifyCryptoHelper )
//{
//  BOOST_MESSAGE( "Verifying CryptoHelper class" );
//
//   generateSecretKey
//
//   computeDerivedKey tested in KeyDerivationFuntiontest.cpp
//
//   isCombinedCipherMode
//
//   isAllowedCipherMode
//
//   isMACRequired
//
//   isCipherTextMACvalid
//
//   overwrite 1
//  VerifyCryptoHelper70();
//  VerifyCryptoHelper71();
//  VerifyCryptoHelper72();
//
//  // overwrite 2
//  VerifyCryptoHelper80();
//  VerifyCryptoHelper81();
//  VerifyCryptoHelper82();
//
//  // copyByteArray
//  VerifyCryptoHelper90();
//  VerifyCryptoHelper91();
//  VerifyCryptoHelper92();
//  VerifyCryptoHelper93();
//  VerifyCryptoHelper94();
//  VerifyCryptoHelper95();
//  VerifyCryptoHelper96();
//  VerifyCryptoHelper97();
//  VerifyCryptoHelper98 );
//
//  // arrayCompare
//  VerifyCryptoHelper100();
//  VerifyCryptoHelper101();
//  VerifyCryptoHelper102();
//  VerifyCryptoHelper103();
//  VerifyCryptoHelper104();
//  VerifyCryptoHelper105();
//  VerifyCryptoHelper106();
//  VerifyCryptoHelper107();
//  VerifyCryptoHelper108 );
//  VerifyCryptoHelper109();
//  //BOOST_REQUIRE( 1 == 1 );
//}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper70 )
{
  bool success = false;

  byte b1[16];
  std::memset(b1, 0xFF, sizeof(b1));

  byte b2[16];
  std::memset(b2, 'A', sizeof(b2));       

  try
    {
      CryptoHelper::overwrite(b1, sizeof(b1), 'A');
      int result = std::memcmp(b1, b2, sizeof(b1));

      success = (result == 0);
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper70 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper71 )
{
  bool success = false;

  try
    {
      CryptoHelper::overwrite(nullptr, 16, 'A');
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper71 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper72 )
{
  bool success = false;

  byte b1[16];

  try
    {
      CryptoHelper::overwrite(b1, 0, 'A');
      success = true;
    }
  catch(...)
    {               
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper72 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper80 )
{
  bool success = false;

  byte b1[16];
  std::memset(b1, 0xFF, sizeof(b1));

  byte b2[16];
  std::memset(b2, '*', sizeof(b2));       

  try
    {
      CryptoHelper::overwrite(b1, sizeof(b1));
      int result = std::memcmp(b1, b2, sizeof(b1));

      success = (result == 0);
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper80 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper81 )
{
  bool success = false;

  try
    {
      CryptoHelper::overwrite(nullptr, 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper81 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper82 )
{
  bool success = false;

  byte b1[16];

  try
    {
      CryptoHelper::overwrite(b1, 0);
      success = true;
    }
  catch(...)
    {               
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper82 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper90 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));

  try
    {
      CryptoHelper::copyByteArray(b1, sizeof(b1), b2, sizeof(b2), 16);
      int result = std::memcmp(b1, b2, sizeof(b1));

      success = (result == 0);
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper90 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper91 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 'A', sizeof(b1));
  std::memset(b2, 'Z', sizeof(b2));

  try
    {
      CryptoHelper::copyByteArray(b1, sizeof(b1), b2, sizeof(b2), 8);

      int result = 0;

      result |= std::memcmp(b1, b2, 8);

      byte aa[8] = { 'A','A','A','A','A','A','A','A' };
      result |= std::memcmp(b1+8, aa, 8);

      success = (result == 0);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper91 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper92 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));

  try
    {
      CryptoHelper::copyByteArray(nullptr, sizeof(b1), b2, sizeof(b2), 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper92 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper93 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));

  try
    {
      CryptoHelper::copyByteArray(b1, 0, b2, sizeof(b2), 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper93 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper94 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));

  try
    {
      CryptoHelper::copyByteArray(b1, sizeof(b1), nullptr, sizeof(b2), 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper94 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper95 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));

  try
    {
      CryptoHelper::copyByteArray(b1, sizeof(b1), b2, 0, 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper95 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper96 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));

  try
    {
      CryptoHelper::copyByteArray(b1, sizeof(b1), b2, sizeof(b2), 32);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper96 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper97 )
{
  bool success = false;

  byte* p = (byte*)(((size_t)-1) - 8);
  byte b[16];

  try
    {
      CryptoHelper::copyByteArray(p, 16, b, sizeof(b), 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper97 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper98 )
{
  bool success = false;

  byte b[16];
  byte* p = (byte*)(((size_t)-1) - 8);    

  try
    {
      CryptoHelper::copyByteArray(b, sizeof(b), p, 16, 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper98 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper100 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = CryptoHelper::arrayCompare(b1, sizeof(b1), b2, sizeof(b2));
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper100 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper101 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0x00, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(b1, sizeof(b1), b2, sizeof(b2));
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper101 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper102 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(b1, sizeof(b1)-1, b2, sizeof(b2));
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper102 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper103 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(b1, sizeof(b1), b2, sizeof(b2)-1);
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper103 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper104 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(nullptr, sizeof(b1), b2, sizeof(b2));
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper104 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper105 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(b1, 0, b2, sizeof(b2));
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper105 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper106 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(b1, sizeof(b1), nullptr, sizeof(b2));
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper106 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper107 )
{
  bool success = false;

  byte b1[16], b2[16];
  std::memset(b1, 0xFF, sizeof(b1));
  std::memset(b2, 0xFF, sizeof(b2));

  try
    {
      success = !CryptoHelper::arrayCompare(b1, sizeof(b1), b2, 0);
    }
  catch(...)
    {
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper107 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper108 )
{
  bool success = false;

  byte* p = (byte*)(((size_t)-1) - 8);
  byte b[16];

  try
    {
      CryptoHelper::arrayCompare(p, 16, b, sizeof(b));
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper108 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper109 )
{
  bool success = false;

  byte b[16];
  byte* p = (byte*)(((size_t)-1) - 8);    

  try
    {
      CryptoHelper::arrayCompare(b, sizeof(b), p, 16);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyCryptoHelper109 failed" );
}
