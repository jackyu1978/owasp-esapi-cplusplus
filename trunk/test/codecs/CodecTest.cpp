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

#include "codecs/Codec.h"
using esapi::Codec;

#include <string>
#include <sstream>

BOOST_AUTO_TEST_CASE(CodecContainsCharacter)
{
  Codec codec;

  BOOST_CHECK(codec.containsCharacter(L'a',L"asdf"));
  BOOST_CHECK(codec.containsCharacter(L's',L"asdf"));
  BOOST_CHECK(codec.containsCharacter(L'd',L"asdf"));
  BOOST_CHECK(codec.containsCharacter(L'f',L"asdf"));
  BOOST_CHECK(codec.containsCharacter(L'b',L"asdf") == false);
  BOOST_CHECK(codec.containsCharacter(L' ',L"asdf") == false);
  BOOST_CHECK(codec.containsCharacter(L'\0',L"asdf") == false);
  BOOST_CHECK(codec.containsCharacter(0,L"") == false);

  BOOST_CHECK(codec.containsCharacter(L'a',(Char*)L"asdf",4));
  BOOST_CHECK(codec.containsCharacter(L'f',(Char*)L"asdf",4));
  BOOST_CHECK(codec.containsCharacter(L'b',(Char*)L"asdf",4) == false);
  BOOST_CHECK(codec.containsCharacter(L' ',(Char*)L"asdf",4) == false);
  BOOST_CHECK(codec.containsCharacter(L'\0',(Char*)L"asdf",4) == false);

  const Char charr[] = { L'a', L's', L'd', L'f' };
  BOOST_CHECK(codec.containsCharacter(L'a',charr,COUNTOF(charr)) == true); 
  BOOST_CHECK(codec.containsCharacter(L's',charr,COUNTOF(charr)) == true); 
  BOOST_CHECK(codec.containsCharacter(L'd',charr,COUNTOF(charr)) == true); 
  BOOST_CHECK(codec.containsCharacter(L'f',charr,COUNTOF(charr)) == true);
  BOOST_CHECK(codec.containsCharacter(L'g',charr,COUNTOF(charr)) == false);
  BOOST_CHECK(codec.containsCharacter(L'a',NULL,COUNTOF(charr)) == false);
  BOOST_CHECK(codec.containsCharacter(L'a',charr,0) == false);
  BOOST_CHECK(codec.containsCharacter(0,0,0) == false);
}

BOOST_AUTO_TEST_CASE( CodecEncode )
{
  Codec codec;

  BOOST_CHECK(codec.encode(L"a",4,L"asdf").compare(L"asdf")==0);
  BOOST_CHECK(codec.encode(L"",4,L"asdf").compare(L"asdf")==0);
}

BOOST_AUTO_TEST_CASE( CodecToHex )
{
	Codec codec;

	BOOST_CHECK(codec.toHex(L'a')[0] == 0x61);
	BOOST_CHECK(codec.toHex(L'b')[0] == 0x62);
	BOOST_CHECK(codec.toHex(L'a')[0] != 0x62);
}

BOOST_AUTO_TEST_CASE( CodecToOctal )
{
	Codec codec;

	BOOST_CHECK(codec.toOctal(L'a')[0] == 0141);
	BOOST_CHECK(codec.toOctal(L'b')[0] == 0142);
	BOOST_CHECK(codec.toOctal(L'a')[0] != 0142);
}

BOOST_AUTO_TEST_CASE( CodecGetHexForNonAlphanumeric )
{
	Codec codec;

	//BOOST_CHECK(codec.getHexForNonAlphanumeric(L'!')[0] == 0x21);
	//BOOST_CHECK_MESSAGE(atoi(codec.getHexForNonAlphanumeric(L'!').c_str()) == 21, "getHexForNonAlphanumeric('!') == " << codec.getHexForNonAlphanumeric(L'!'));
	//BOOST_CHECK(atoi(codec.getHexForNonAlphanumeric(L'"').c_str()) == 22);
	BOOST_CHECK(codec.getHexForNonAlphanumeric(L'!')[0] != 22);

	//BOOST_CHECK(atoi(codec.getHexForNonAlphanumeric(L'a').c_str()) == 0);
}
