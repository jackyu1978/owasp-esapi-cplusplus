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

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"
#include <codecs/Codec.h>

#include <string>
#include <sstream>


using esapi::Codec;

BOOST_AUTO_TEST_CASE( CodecContainsCharacter)
{
  Codec codec;

  BOOST_CHECK(codec.containsCharacter('a',"asdf"));
  BOOST_CHECK(codec.containsCharacter('f',"asdf"));
  BOOST_CHECK(codec.containsCharacter('b',"asdf") == false);
  BOOST_CHECK(codec.containsCharacter(' ',"asdf") == false);
  BOOST_CHECK(codec.containsCharacter('\0',"asdf") == false);
  BOOST_CHECK(codec.containsCharacter(0,"") == false);

  BOOST_CHECK(codec.containsCharacter('a',(char*)"asdf",4));
  BOOST_CHECK(codec.containsCharacter('f',(char*)"asdf",4));
  BOOST_CHECK(codec.containsCharacter('b',(char*)"asdf",4) == false);
  BOOST_CHECK(codec.containsCharacter(' ',(char*)"asdf",4) == false);
  BOOST_CHECK(codec.containsCharacter('\0',(char*)"asdf",4) == false);
  BOOST_CHECK(codec.containsCharacter(0,0,0) == false);
}

BOOST_AUTO_TEST_CASE( CodecEncode )
{
  Codec codec;

  BOOST_CHECK(codec.encode("a",4,"asdf").compare("asdf")==0);
  BOOST_CHECK(codec.encode("",4,"asdf").compare("asdf")==0);
}

BOOST_AUTO_TEST_CASE( CodecToHex )
{
	Codec codec;

	BOOST_CHECK(codec.toHex('a')[0] == 0x61);
	BOOST_CHECK(codec.toHex('b')[0] == 0x62);
	BOOST_CHECK(codec.toHex('a')[0] != 0x62);
}

BOOST_AUTO_TEST_CASE( CodecToOctal )
{
	Codec codec;

	BOOST_CHECK(codec.toOctal('a')[0] == 0141);
	BOOST_CHECK(codec.toOctal('b')[0] == 0142);
	BOOST_CHECK(codec.toOctal('a')[0] != 0142);
}

BOOST_AUTO_TEST_CASE( CodecGetHexForNonAlphanumeric )
{
	Codec codec;

	//BOOST_CHECK(codec.getHexForNonAlphanumeric('!')[0] == 0x21);
	BOOST_CHECK_MESSAGE(atoi(codec.getHexForNonAlphanumeric('!').c_str()) == 21, "getHexForNonAlphanumeric('!') == " << codec.getHexForNonAlphanumeric('!'));
	BOOST_CHECK(atoi(codec.getHexForNonAlphanumeric('"').c_str()) == 22);
	BOOST_CHECK(codec.getHexForNonAlphanumeric('!')[0] != 22);

	BOOST_CHECK(atoi(codec.getHexForNonAlphanumeric('a').c_str()) == 0);
}
