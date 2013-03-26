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

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;
using esapi::StringArray;

#include "codecs/Codec.h"
using esapi::Codec;

#include "codecs/MySQLCodec.h"
using esapi::MySQLCodec;

#include <iostream>
#include <string>
#include <sstream>

BOOST_AUTO_TEST_CASE( MySQLCodecBasicTest )
{
	BOOST_CHECK(MySQLCodec::ANSI_MODE == 1);

	MySQLCodec mySQLCodecANSI( MySQLCodec::ANSI_MODE );
	MySQLCodec mySQLCodecStandard( MySQLCodec::MYSQL_MODE );

	StringArray immune;
	String result = "";

	BOOST_CHECK( mySQLCodecANSI.encode(immune, "\'") == String("\'\'") );
	BOOST_CHECK( mySQLCodecStandard.encode(immune, "<").compare("\\<") == 0 );

	result = mySQLCodecStandard.decode("\\<");
	BOOST_CHECK( result == "<" );

	BOOST_CHECK( mySQLCodecANSI.decode("\'\'").compare("\'") == 0 );
}

BOOST_AUTO_TEST_CASE(testMySQLStandardEncodeChar0x100)
{
	MySQLCodec mySQLCodecStandard( MySQLCodec::MYSQL_MODE );
	StringArray immune;

	Char in = (Char)0x10;
	String expected = "\\" + String(1,in);
	String result;

	result = mySQLCodecStandard.encodeCharacter(immune, String(1,in));

	// this should be escaped
	BOOST_CHECK(expected.compare(result) == 0);
}

BOOST_AUTO_TEST_CASE( MySQLCodecInvalidModeTest )
{
	BOOST_CHECK(MySQLCodec::ANSI_MODE == 1);

  MySQLCodec mySQLCodecBogus( MySQLCodec::Mode(99) );

	StringArray immune;
	String result = "";

	BOOST_CHECK( mySQLCodecBogus.encode(immune, "\'") == String("\'\'") );
	BOOST_CHECK( mySQLCodecBogus.encode(immune, "<").compare("\\<") == 0 );

	result = mySQLCodecBogus.decode("\\<");
	BOOST_CHECK( result == "<" );

	BOOST_CHECK( mySQLCodecBogus.decode("\'\'").compare("\'") == 0 );
}
