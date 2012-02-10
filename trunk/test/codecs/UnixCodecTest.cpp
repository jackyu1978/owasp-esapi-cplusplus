/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Daniel Amodio, dan.amodio@aspectsecurity.com
 *
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

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;
using esapi::StringStream;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <map>
#include <set>

#include "util/TextConvert.h"
using esapi::TextConvert;

#include "codecs/UnixCodec.h"
using esapi::UnixCodec;

BOOST_AUTO_TEST_CASE( UnixCodecTestCase_1P )
{
	esapi::UnixCodec uc;
	//BOOST_CHECK_MESSAGE(uc.encodeCharacter(L"",0,L'a').compare(L"a")==0, L"uc.encodeCharacter(\"\",0,L'a') ==" << uc.encodeCharacter(L"",0,L'a'));
}

BOOST_AUTO_TEST_CASE( UnixCodecTestCase_2P )
{
	esapi::UnixCodec uc;
	//BOOST_CHECK_MESSAGE(uc.encodeCharacter(L"a",1,L'a').compare(L"a")==0, L"uc.encodeCharacter(\"a\",1,L'a') ==" << uc.encodeCharacter(L"a",1,L'a'));
}

BOOST_AUTO_TEST_CASE( UnixCodecTestCase_3P )
{
	esapi::UnixCodec uc;
	//BOOST_CHECK_MESSAGE(uc.encodeCharacter(L"",0,L'<').compare(L"\\<")==0, L"=" << uc.encodeCharacter(L"",0,L'<'));
}

BOOST_AUTO_TEST_CASE( UnixCodecTestCase_4P )
{
	esapi::UnixCodec uc;
	//BOOST_CHECK(uc.encodeCharacter(L"",0,L'\\').compare(L"\\\\")==0);
}

