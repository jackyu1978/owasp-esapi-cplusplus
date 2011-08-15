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
}

BOOST_AUTO_TEST_CASE( CodecEncode )
{
  Codec codec;

  BOOST_CHECK(codec.encode("a",4,"asdf").compare("asdf")==0);
}
