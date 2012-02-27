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
 * @author Andrew Durkin, atdurkin@gmail.com
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

#include <exception>
using std::exception;

#include "EsapiCommon.h"
using esapi::String;

#include "errors/NoSuchAlgorithmException.h"
using esapi::NoSuchAlgorithmException;

#include "errors/IllegalArgumentException.h"
using esapi::IllegalArgumentException;

#include "util/SecureArray.h"
using esapi::SecureByteArray;

#include <crypto/CipherSpec.h>
using esapi::CipherSpec;

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction1) //:Test correct construction.
{
  try
    {
      SecureByteArray myIV;
      CipherSpec cs(L"AES/CBC/NoPadding", 128, 8, myIV);
      BOOST_CHECK(cs.getCipherTransformation() == L"AES/CBC/NoPadding");
      BOOST_CHECK(cs.getKeySize() == 128);
      BOOST_CHECK(cs.getBlockSize() == 8);
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


BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction2) //:Test empty cipher XForm.
{
  bool caughtExcept = false;
  try
    {
      SecureByteArray myIV;
      CipherSpec cs(L"", 128, 8, myIV);
    }
  catch(const NoSuchAlgorithmException&)
    {
      caughtExcept = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK(caughtExcept);
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction3) //:Missing padding scheme.
{
  bool caughtExcept = false;
  try
    {
      SecureByteArray myIV;
      CipherSpec cs(L"AES/CBC", 128, 8, myIV);
    }
  catch(const NoSuchAlgorithmException&)
    {
      caughtExcept = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK(caughtExcept);
}


BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction4) //:Checking CipherSpec(SecureByteArray &b) CTOR.
{
  try
    {
      SecureByteArray myIV;
      CipherSpec cs(myIV);
    }
  catch(const NoSuchAlgorithmException&)
    {
      // An empty A/M/P causes an NoSuchAlgorithmException
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

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction5) //:Checking set and get CipherTransformation().
{
  bool caughtExcept = false;
  try
    {
      CipherSpec cs(L"AlgName/Mode/Padding", 128);
      BOOST_CHECK(cs.getCipherTransformation() == L"AlgName/Mode/Padding");

      cs.setCipherTransformation(L"");
    }
  catch(const NoSuchAlgorithmException&)
    {
      caughtExcept = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK(caughtExcept);
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction6) //:Testing a bunch of get functions.
{
  try
    {
      CipherSpec cs(L"Blowfish/CBC/PKCS5Padding", 128, 8);
      BOOST_CHECK(cs.getKeySize() == 128);
      BOOST_CHECK(cs.getBlockSize() == 8);
      BOOST_CHECK(cs.getCipherTransformation() == L"Blowfish/CBC/PKCS5Padding");
      BOOST_CHECK(cs.getCipherAlgorithm() == L"Blowfish");
      BOOST_CHECK(cs.getCipherMode() == L"CBC");
      BOOST_CHECK(cs.getPaddingScheme() == L"PKCS5Padding");
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

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction7) //:Testing setBlockSize().
{
  bool caughtExcept = false;
  try
    {
      CipherSpec cs;
      cs.setBlockSize(0);
    }
  catch(const IllegalArgumentException&)
    {
      caughtExcept = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK(caughtExcept);

#if 0
  caughtExcept = false;
  try
    {
      cs.setBlockSize(-1);
    }
  catch(const NoSuchAlgorithmException&)
    {
      caughtExcept = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK(caughtExcept);
#endif
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction8) //:Testing requiresIV().
{
  try
    {
      CipherSpec cs(L"AeS/EcB/nOpADDING", 128);
      BOOST_CHECK(cs.getCipherAlgorithm() == L"AES");
      BOOST_CHECK(cs.getCipherMode() == L"ECB");
      BOOST_CHECK(cs.getPaddingScheme() == L"NoPadding");
      BOOST_CHECK(cs.requiresIV() == false);
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

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction9) //:Testing requiresIV().
{
  try
    {
      CipherSpec cs(L"AES/CBC/None", 128);
      BOOST_CHECK(cs.requiresIV() == true);
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

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction10) //:Testing assignment operator.
{
  try
    {
      CipherSpec spec1(L"AES/CBC/None", 128, 16);
      CipherSpec spec2(L"Blowfish/CBC/PKCS5Padding", 64, 8);
      spec1 = spec2;
      BOOST_CHECK(spec1.getCipherTransformation() == L"Blowfish/CBC/PKCS5Padding");
      BOOST_CHECK(spec1.getKeySize() == 64);
      BOOST_CHECK(spec1.getBlockSize() == spec2.getBlockSize());
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

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction11) //:Testing Copy CTOR.
{
  try
    {
      CipherSpec spec1(L"AES/CBC/None", 128, 16);
      CipherSpec spec2(spec1);
      BOOST_CHECK(spec2.equals(spec1));
      BOOST_CHECK(spec1.getCipherTransformation() == spec2.getCipherTransformation());
      BOOST_CHECK(spec1.getKeySize() == spec2.getKeySize());
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

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction12) //:Testing equals function.
{
  try
    {
      SecureByteArray myIV;
      CipherSpec spec1(L"AES/CBC/None", 128, 16, myIV);
      CipherSpec spec2(L"Blowfish/CBC/PKCS5Padding", 64, 8);
      BOOST_CHECK(spec1.equals(spec1));
      BOOST_CHECK(!spec1.equals(spec2));
      spec2 = spec1;
      BOOST_CHECK(spec1.equals(spec2));
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