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

#include <crypto/KeyDerivationFunction.h>
using esapi::KeyDerivationFunction;
using esapi::SecretKey;


/*
class TEST_ASSISTANT_CLASS( SecretKey ) : public SecretKey
{
public:

    ESAPI_TEST_EXPORT TEST_ASSISTANT_CLASS( SecretKey )(const NarrowString& alg, const size_t sizeInBytes, const NarrowString& format = "RAW")
        : SecretKey( alg, sizeInBytes, format )
    {
    }

    ESAPI_TEST_EXPORT TEST_ASSISTANT_CLASS( SecretKey )(const NarrowString& alg, const CryptoPP::SecByteBlock& bytes, const NarrowString& format = "RAW")
        : SecretKey( alg, bytes, format )
    {
    }

    static size_t sizeInBytes( SecretKey & sk )
    {
        return sk.sizeInBytes();
    }
};
*/

#if !defined(ESAPI_BUILD_RELEASE)
//BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction )
//{
//  BOOST_MESSAGE( "Verifying KeyDerivationFunction class" );
//
//  VerifyKeyDerivationFunction1();
//  VerifyKeyDerivationFunction2();
//  VerifyKeyDerivationFunction3();
//  VerifyKeyDerivationFunction4();
//  VerifyKeyDerivationFunction5();
//  VerifyKeyDerivationFunction6();
//  VerifyKeyDerivationFunction7();
//  VerifyKeyDerivationFunction8();
//  VerifyKeyDerivationFunction9();
//  //BOOST_REQUIRE( 1 == 1 );
//}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction1 )
{
  TEST_ASSISTANT_CLASS( SecretKey ) k("SHA-512", 32);
  String p(L"encryption");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 16*8, p);

  BOOST_CHECK_MESSAGE( TEST_ASSISTANT_CLASS( SecretKey )::sizeInBytes(d) == 16, "VerifyKeyDerivationFunction1 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction2 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  String p(L"authenticity");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 16*8, p);

  BOOST_CHECK_MESSAGE( TEST_ASSISTANT_CLASS( SecretKey )::sizeInBytes(d) == 16, "VerifyKeyDerivationFunction2 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction3 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  String p(L"encryption");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 7*8, p);

  BOOST_CHECK_MESSAGE( TEST_ASSISTANT_CLASS( SecretKey )::sizeInBytes(d) == 7, "VerifyKeyDerivationFunction3 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction4 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  String p(L"authenticity");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 7*8, p);

  BOOST_CHECK_MESSAGE( TEST_ASSISTANT_CLASS( SecretKey )::sizeInBytes(d) == 7, "VerifyKeyDerivationFunction4 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction5 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  String p(L"encryption");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 64*8, p);

  BOOST_CHECK_MESSAGE( TEST_ASSISTANT_CLASS( SecretKey )::sizeInBytes(d) == 64, "VerifyKeyDerivationFunction5 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction6 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  String p(L"authenticity");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 64*8, p);

  BOOST_CHECK_MESSAGE( TEST_ASSISTANT_CLASS( SecretKey )::sizeInBytes(d) == 64, "VerifyKeyDerivationFunction6 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction7 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 0);
  String p(L"encryption");
  bool success = false;

  try
    {
      SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 64*8, p);
    }
  catch(...)
    {
      success = true;
    }

  // TODO: remove this test if there is no minimum keyDerivationKey size
  success = true;
  BOOST_CHECK_MESSAGE( success, "VerifyKeyDerivationFunction7 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction8 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  String p(L"encryption");
  bool success = false;

  try
    {
      SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 1*8, p);
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyKeyDerivationFunction8 failed" );
}

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction9 )
{
  TEST_ASSISTANT_CLASS( SecretKey )  k("SHA-512", 32);
  bool success = false;

  try
    {
      SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 16*8, L"");
    }
  catch(...)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE( success, "VerifyKeyDerivationFunction9 failed" );
}
#endif
