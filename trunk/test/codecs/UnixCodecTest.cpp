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

#include "codecs/UnixCodec.h"
using esapi::UnixCodec;


BOOST_AUTO_TEST_CASE( UnixCodecTestCase )
{
	esapi::UnixCodec uc;
	BOOST_CHECK_MESSAGE(uc.encodeCharacter("",0,'a').compare("a")==0, "uc.encodeCharacter(\"\",0,'a') ==" << uc.encodeCharacter("",0,'a'));
	BOOST_CHECK_MESSAGE(uc.encodeCharacter("a",1,'a').compare("a")==0, "uc.encodeCharacter(\"a\",1,'a') ==" << uc.encodeCharacter("a",1,'a'));
	BOOST_CHECK_MESSAGE(uc.encodeCharacter("",0,'<').compare("\\<")==0, "=" << uc.encodeCharacter("",0,'<'));
	BOOST_CHECK(uc.encodeCharacter("",0,'\\').compare("\\\\")==0);
}

