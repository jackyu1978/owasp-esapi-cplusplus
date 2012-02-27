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
using esapi::Char;
using esapi::String;
using esapi::StringStream;

#include <reference/DefaultEncryptor.h>
using esapi::DefaultEncryptor;

#include <errors/EncryptionException.h>
using esapi::EncryptionException;

#include <errors/IllegalArgumentException.h>
using esapi::IllegalArgumentException;

#include "util/TextConvert.h"
using esapi::TextConvert;

void VerifyEncrypt1();
void VerifyEncrypt2();
void VerifyDecrypt1();
void VerifyDecrypt2();
void VerifySign();
void VerifyVerifySignature();
void VerifySeal();
void VerifyUnseal();
void VerifyVerifySeal();

// The C++ code perfoms the same DefaultEncryptor::X(...) as JavaEncrytor.java,
// See http://owasp-esapi-java.googlecode.com/svn/trunk/src/main/java/org/owasp/esapi/reference/crypto/JavaEncryptor.java.

BOOST_AUTO_TEST_CASE( VerifyDefaultEncryptor )
{
  BOOST_MESSAGE( "Verifying DefaultEncryptor class" );

  // VerifyEncrypt1();
  // VerifyEncrypt2();
  // VerifyDecrypt1();
  // VerifyDecrypt2();
  // VerifySign();
  // VerifyVerifySignature();
  // VerifySeal();
  // VerifyUnseal();
  // VerifyVerifySeal();
}

BOOST_AUTO_TEST_CASE( VerifyHash1 )
{
  // String data
  String password = L"password", salt = L"salt", encoded;
  bool success = false;
  const String expected = L"9Lw+bODsCpRW/wNyzapmC5xyOrF7fx/G0C46LKshoByzQ8gqSNlnJ91e+eWR5nsr58GGGLdoYRbgwYRVTrHjLQ==";

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);
      
      success = (encoded == expected);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (expected): " << TextConvert::WideToNarrow(expected) << ", (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash2 )
{
  // String data
  String password = L"", salt = L"", encoded;
  bool success = false;
  const String expected = L"FuSGJAO03JV8sK4jUlegyguthHIQhV+36IeDLOMM8E3B00Q4rheRCv5TyLYkfwhFLINcNP2e4/ywpnPsY1JjNA==";
    
  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);
      
      success = (encoded == expected);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (expected): " << TextConvert::WideToNarrow(expected) << ", (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash3 )
{
  // String data
  String password = L"password", salt = L"", encoded;
  bool success = false;
  const String expected = L"04jstQ3C1a7zALLbnqGvvNqDsCcnIY65dADzjDKy3dl1H8Oao0vE1Sf43dftLwKKUdPcGN2EYEF8Nprh+nq3mg==";
    
  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);
      
      success = (encoded == expected);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (expected): " << TextConvert::WideToNarrow(expected) << ", (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash4 )
{
  // String data
  String password = L"", salt = L"salt", encoded;
  bool success = false;
  const String expected = L"Ta2RUilim/6vxzx0nlUWoloMv4J1kZyLWsT5woi3FOidFT65XjA6Z2umi/Pfs60ebtJTzuMZFTcGvsByk4QA6g==";

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);
      
      success = (encoded == expected);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (expected): " << TextConvert::WideToNarrow(expected) << ", (calculated): " << TextConvert::WideToNarrow(encoded));
}

