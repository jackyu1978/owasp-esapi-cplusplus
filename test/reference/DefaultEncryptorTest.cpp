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

#if !defined(ESAPI_OS_WINDOWS)
# define BOOST_TEST_DYN_LINK
# include <boost/test/unit_test.hpp>
using namespace boost::unit_test;
#endif

#include <string>
using std::string;

#include <reference/DefaultEncryptor.h>
using esapi::DefaultEncryptor;

#include <errors/EncryptionException.h>
using esapi::EncryptionException;

#include <errors/InvalidArgumentException.h>
using esapi::InvalidArgumentException;

void VerifyHash();
void VerifyHash1();
void VerifyHash2();
void VerifyHash3();
void VerifyHash4();
void VerifyHash5();

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

  VerifyHash();
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

void VerifyHash()
{
  VerifyHash1();
  VerifyHash2();
  VerifyHash3();
  VerifyHash4();
  VerifyHash5();
}

void VerifyHash1()
{
  // String data
  string password = "password", salt = "salt", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const string expected = "KYiahqQx3B2tJ8B8E+6FUqbD3K6UBwVoUrH6SnliOwXEe4GVHMn0pPtBiApZAmwdj7J926DUL4sk5UrE6u8bIw==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << encoded);
}

void VerifyHash2()
{
  // Random binary data
  byte p[] = { 213,75,186,206,204,235,120,11 };
  byte s[] = { 242,153,45,232,101,16,15,224 };

  string password((char*)p, sizeof(p)), salt((char*)s, sizeof(s)), encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const string expected = "dLaQQLg7HsFej/So/DcUa5vsIOHSUj9aGcl/z64i7E4tw+2mg+PV7S/OmejoQ6got1bruemmoDij0HMjLz+2ZA==";

      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << encoded);
}

void VerifyHash3()
{
  // String data
  string password = "", salt = "", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const string expected = "0TWsPVOabzwKNp6kYU+oM2vrCKwfchfjkb4amCuFaYxqK3lvBiPDH6AjsAmpEVwitmlU+8HCXUouWlCzNIZz6w==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << encoded);
}

void VerifyHash4()
{
  // String data
  string password = "password", salt = "", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const string expected = "l0g3Av17sYmQFFkdlrskfxpGBuyKhwMg8hvoklaa0fIKV224f0tv4/B2Y0+ckuxjaBnldK86l310EKyYsHsCNQ==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << encoded);
}

void VerifyHash5()
{
  // String data
  string password = "", salt = "salt", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const string expected = "v+HgWZYnwBxngZGeHgbzMzym0ROd5mRPTIrpdmeTlMoApHj/gCwUfajLWMqZHUoKDgzhgb5gSiECLzDUU9Gacg==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }

  BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << encoded);
}
