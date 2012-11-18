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

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;

#include "reference/DefaultEncoder.h"
#include "codecs/Codec.h"
#include "codecs/UnixCodec.h"
using esapi::UnixCodec;
using esapi::DefaultEncoder;


using std::shared_ptr;

#if !defined(ESAPI_BUILD_RELEASE)
BOOST_AUTO_TEST_CASE( DefaultEncoderTestCase )
{
	esapi::DefaultEncoder de;
	shared_ptr<UnixCodec>uc1(new esapi::UnixCodec);

	String encoded = de.encodeForOS(uc1.get(), L"asdf<");
	BOOST_CHECK(encoded.compare(L"asdf\\<") == 0);

	shared_ptr<UnixCodec>uc2(new esapi::UnixCodec);
	BOOST_CHECK(de.encodeForOS(uc2.get(), L"sdf:ff").compare(L"sdf\\:ff")==0);

	encoded = de.encodeForBase64(L"asdf");
	BOOST_CHECK(encoded.compare(L"YXNkZg==") == 0); //base64 value of `asdf`
	BOOST_CHECK(de.decodeFromBase64(encoded).compare(L"asdf")==0);

	BOOST_CHECK(de.encodeForLDAP(L"asd\\f").compare(L"asd\\5cf")==0);

}
#endif

