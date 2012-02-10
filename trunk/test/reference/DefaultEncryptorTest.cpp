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

#if defined(_WIN32)
    #if defined(STATIC_TEST)
        // do not enable BOOST_TEST_DYN_LINK
    #elif defined(DLL_TEST)
        #define BOOST_TEST_DYN_LINK
    #else
        #error "For Windows you must define either STATIC_TEST or DLL_TEST"
    #endif
#else
    #define BOOST_TEST_DYN_LINK
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

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"wt4mxWv9iVZIxx2zwhmcuFBWMKu3TDZ9JamhDF7TI01KImF1fLtFitpJGKEzZJzA+D3GUg/3/itlRfDY+RAn6g==";
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

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash2 )
{
  // String data
  String password = L"", salt = L"", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"meQnjDp11bpZqktCNsYaPUVfUnptYoCTS54pozGtW6eUmPPLv903Ik31umRQWUtyBVwpR/6Rbw3VnBWbX9UKnQ==";
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

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash3 )
{
  // String data
  String password = L"password", salt = L"", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"y9XYKzJ5rFcfsWTQHdt5HI3nxHGsa273FxBWKEpc0y/q1Nk/oz6Dx1WNLPwQHZHW1CQuTuu7JnMKs5ZQioRegg==";
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

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash4 )
{
  // String data
  String password = L"", salt = L"salt", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"8jWD+85WZUZroRcI1uYKy3PimirMqUbcr+dNVJDeGIFqbB6QkMcPVpkeeTEqr/ptJq32uG6bmjphrHzX+xrTOg==";
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

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

