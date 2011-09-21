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

#define BOOST_TEST_DYN_LINK
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

#include <errors/InvalidArgumentException.h>
using esapi::InvalidArgumentException;

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

      const String expected = L"KYiahqQx3B2tJ8B8E+6FUqbD3K6UBwVoUrH6SnliOwXEe4GVHMn0pPtBiApZAmwdj7J926DUL4sk5UrE6u8bIw==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR(L"Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR(L"Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR(L"Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash2 )
{
  // Random binary data
  byte p[] = { 213,75,186,206,204,235,120,11 };
  byte s[] = { 242,153,45,232,101,16,15,224 };

  String password((Char*)p, sizeof(p)), salt((Char*)s, sizeof(s)), encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"dLaQQLg7HsFej/So/DcUa5vsIOHSUj9aGcl/z64i7E4tw+2mg+PV7S/OmejoQ6got1bruemmoDij0HMjLz+2ZA==";

      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR(L"Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR(L"Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR(L"Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash3 )
{
  // String data
  String password = L"", salt = L"", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"0TWsPVOabzwKNp6kYU+oM2vrCKwfchfjkb4amCuFaYxqK3lvBiPDH6AjsAmpEVwitmlU+8HCXUouWlCzNIZz6w==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR(L"Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR(L"Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR(L"Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash4 )
{
  // String data
  String password = L"password", salt = L"", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"l0g3Av17sYmQFFkdlrskfxpGBuyKhwMg8hvoklaa0fIKV224f0tv4/B2Y0+ckuxjaBnldK86l310EKyYsHsCNQ==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR(L"Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR(L"Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR(L"Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

BOOST_AUTO_TEST_CASE( VerifyHash5 )
{
  // String data
  String password = L"", salt = L"salt", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"v+HgWZYnwBxngZGeHgbzMzym0ROd5mRPTIrpdmeTlMoApHj/gCwUfajLWMqZHUoKDgzhgb5gSiECLzDUU9Gacg==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR(L"Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR(L"Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR(L"Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));
}

