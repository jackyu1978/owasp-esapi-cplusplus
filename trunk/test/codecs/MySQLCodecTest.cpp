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
using esapi::Char;
using esapi::String;

#include "codecs/Codec.h"
using esapi::Codec;

#include "codecs/MySQLCodec.h"
using esapi::MySQLCodec;

#include <string>
#include <sstream>

BOOST_AUTO_TEST_CASE( MySQLCodecBasicTest )
{
	BOOST_CHECK(MySQLCodec::ANSI_MODE == 1);

	MySQLCodec mySQLCodecANSI( MySQLCodec::ANSI_MODE );
	MySQLCodec mySQLCodecStandard( MySQLCodec::MYSQL_MODE );

	const Char immune[] = { 0 };
	String result = L"";

	BOOST_CHECK( mySQLCodecANSI.encode(immune,0, L"\'") == String(L"\'\'") );
	BOOST_CHECK( mySQLCodecStandard.encode(immune,0, L"<").compare(L"\\<") == 0 );

	result = mySQLCodecStandard.decode(L"\\<");
	BOOST_CHECK( result == L"<" );

	BOOST_CHECK( mySQLCodecANSI.decode(L"\'\'").compare(L"\'") == 0 );
}


BOOST_AUTO_TEST_CASE(testMySQLStandardEncodeChar0x100)
{
	MySQLCodec mySQLCodecStandard( MySQLCodec::MYSQL_MODE );
	const Char immune[] = { 0 };

	Char in = (Char)0x100;
	String inStr = String(1,(Char)0x100);
	String expected = L"\\" + String(1,(Char)0x100);
	String result;

	result = mySQLCodecStandard.encodeCharacter(immune, 0, in);

	//std::wcout << L"in:" << in << L" inStr: " << inStr << L" expected: " << expected << L" result: " << result;

	// this should be escaped
	BOOST_CHECK(! inStr.compare(result) == 0);
	BOOST_CHECK(expected.compare(result) == 0);
}


