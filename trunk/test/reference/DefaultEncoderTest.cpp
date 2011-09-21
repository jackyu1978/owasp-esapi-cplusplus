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

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using String;

#include <map>
#include <set>

#include <sstream>
using Stringstream;
using std::istringstream;
using std::ostringstream;

#include "reference/DefaultEncoder.h"
#include "codecs/Codec.h"
#include "codecs/UnixCodec.h"
using esapi::UnixCodec;
using esapi::DefaultEncoder;

#include <boost/shared_ptr.hpp>
using boost::shared_ptr;

#if !defined(ESAPI_BUILD_RELEASE)
BOOST_AUTO_TEST_CASE( DefaultEncoderTestCase )
{
	esapi::DefaultEncoder de;
	shared_ptr<UnixCodec>uc1(new esapi::UnixCodec);

	String encoded = de.encodeForOS(uc1.get(), "asdf<");
	BOOST_CHECK(encoded.compare("asdf\\<") == 0);

	shared_ptr<UnixCodec>uc2(new esapi::UnixCodec);
	BOOST_CHECK(de.encodeForOS(uc2.get(), "sdf:ff").compare("sdf\\:ff")==0);

	encoded = de.encodeForBase64("asdf");
	BOOST_CHECK(encoded.compare("YXNkZg==") == 0); //base64 value of `asdf`
	BOOST_CHECK(de.decodeFromBase64(encoded).compare("asdf")==0);

	BOOST_CHECK(de.encodeForLDAP("asd\\f").compare("asd\\5cf")==0);

}
#endif

