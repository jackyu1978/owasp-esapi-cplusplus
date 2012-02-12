/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Dan Amodio, dan.amodio@aspectsecurity.com
 */

#include <iostream>

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

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;

#include "codecs/PushbackString.h"
using esapi::PushbackString;


class TEST_ASSISTANT_CLASS( PushbackString )
{
public:
    static String GetInput( PushbackString & pbs )
    {
        return pbs.input;
    }

    static void SetInput( PushbackString & pbs, String & str )
    {
        pbs.input = str;
    }
};
 

#if !defined(ESAPI_BUILD_RELEASE)
BOOST_AUTO_TEST_CASE( PushbackStringHasNext )
{
  PushbackString pbs(L"asdf");

  BOOST_CHECK(pbs.index() == 0);
  // original 2012.01.29 jAH
  // BOOST_CHECK(pbs.input.compare(L"asdf") == 0);
  BOOST_CHECK( (esapi::TEST_ASSISTANT_CLASS( PushbackString )::GetInput( pbs )).compare(L"asdf") == 0 );
  BOOST_CHECK(pbs.hasNext());

  // original 2012.01.29 jAHOLMES
  // pbs.input = L"";
  esapi::TEST_ASSISTANT_CLASS( PushbackString )::SetInput( pbs, String( L"" ) );
  BOOST_CHECK(pbs.hasNext() == false);
}
#endif

BOOST_AUTO_TEST_CASE( PushbackStringNext )
{
  PushbackString pbs(L"asdf");

  Char next = pbs.next();

  BOOST_CHECK_MESSAGE(next == L'a', "On string 'asdf' next() returned '" << next << "'");
  BOOST_CHECK(next != 0);

  pbs.pushback(L'x');
  next = pbs.next();
  BOOST_CHECK(next != 0);
  BOOST_CHECK(next != L'a');
  BOOST_CHECK(next == L'x');

  next = pbs.next();
  BOOST_CHECK(next == L's');

  next = pbs.next();
  BOOST_CHECK(next == L'd');

  next = pbs.next();
  BOOST_CHECK(next == L'f');

  next = pbs.next();
  BOOST_CHECK(next == 0);

  next = pbs.next();
  BOOST_CHECK(next == 0);

}

BOOST_AUTO_TEST_CASE( PushbackStringIsHexDigit )
{
  PushbackString pbs(L"asdf");

  BOOST_CHECK(pbs.isHexDigit(L'a'));
  BOOST_CHECK(pbs.isHexDigit(L'f'));
  BOOST_CHECK(pbs.isHexDigit(L'3'));
  BOOST_CHECK(pbs.isHexDigit(L'E'));
  BOOST_CHECK(!pbs.isHexDigit(L'l'));
  BOOST_CHECK(!pbs.isHexDigit(L'P'));
  BOOST_CHECK(!pbs.isHexDigit(L'#'));
}

BOOST_AUTO_TEST_CASE( PushbackStringIsOctalDigit )
{
  PushbackString pbs(L"asdf");

  BOOST_CHECK(pbs.isOctalDigit(L'1'));
  BOOST_CHECK(pbs.isOctalDigit(L'7'));
  BOOST_CHECK(!pbs.isOctalDigit(L'9'));
  BOOST_CHECK(!pbs.isOctalDigit(L'b'));
}

BOOST_AUTO_TEST_CASE( PushbackStringNextHex )
{
  PushbackString pbs(L"asdf");

  Char next = pbs.nextHex();
  BOOST_CHECK(next == 0x61);
  BOOST_CHECK(next == L'a');
  BOOST_CHECK(next != 0);

  next = pbs.nextHex();

  // s is not hex
  BOOST_CHECK(next == 0);
}

#if !defined(ESAPI_BUILD_RELEASE)
BOOST_AUTO_TEST_CASE( PushbackStringNextOctal )
{
  PushbackString pbs(L"141");

  Char next = pbs.nextOctal();
  BOOST_CHECK_MESSAGE(next == L'1', "nextOctal() on 'asdf' returned '" << next << "'");
  BOOST_CHECK(next != 0);

  // original 2012.01.29 jAHOLMES
  // pbs.input = L"9999";
  esapi::TEST_ASSISTANT_CLASS( PushbackString )::SetInput( pbs, String( L"9999" ) );
  next = pbs.nextOctal();
  BOOST_CHECK(next == 0);
}
#endif

BOOST_AUTO_TEST_CASE( PushbackStringTest2 )
{
  PushbackString pbs(L"asdf");

  BOOST_CHECK(true);
}

