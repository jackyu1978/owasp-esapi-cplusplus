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
using std::cout;
using std::cerr;
using std::endl;

#include <iomanip>
using std::hex;
using std::setfill;
using std::setw;

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"
#include <codecs/LDAPCodec.h>
using esapi::LDAPCodec;

#include <string>
#include <sstream>
using std::string;
using std::ostringstream;

#define HEX(x) std::hex << std::setw(x) << std::setfill('0')
#define OCT(x) std::octal << std::setw(x) << std::setfill('0')

BOOST_AUTO_TEST_CASE(LDAPCodecTest_1P)
{
  // Positive test - construction
  LDAPCodec codec;
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_2P)
{
  // Positive test - copy
  LDAPCodec codec1;
  LDAPCodec codec2(codec1);
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_3P)
{
  // Positive test - assignment
  LDAPCodec codec1;
  LDAPCodec codec2 = codec1;
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_4N)
{
  // Negative test
  LDAPCodec codec;

  string encoded = codec.encode(NULL, 0, 'A');
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_5N)
{
  // Negative test
  LDAPCodec codec;
  const char immune[] = { (char)0xFF };
  string encoded = codec.encode(immune, 0, 'A');
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_6N)
{
  // Negative test
  LDAPCodec codec;
  const char immune[] = { (char)0xFF };
  string encoded = codec.encode(NULL, COUNTOF(immune), 'A');
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_7P)
{
  // Positive test
  LDAPCodec codec;
  const char immune[] = { (char)0xFF };

  for( unsigned int c = 'A'; c <= 'Z'; c++)
  {
    string encoded = codec.encode(immune, COUNTOF(immune), (char)c);
    BOOST_CHECK((encoded == string(1, c)), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_8P)
{
  // Positive test
  LDAPCodec codec;
  const char special[] = { (char)0x28, (char)0x29, (char)0x2a, (char)0x5c, (char)0x00 };
  const char immune[] = { (char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(special); i++ )
  {
    const string encoded = codec.encode(immune, COUNTOF(immune), special[i]);

    ostringstream oss;
    oss << "\\\\" << HEX(2) << special[i];
    const string expected = oss.str();

    BOOST_CHECK((encoded == expected), "Failed to encode character");
  }

  BOOST_AUTO_TEST_CASE(LDAPCodecTest_9P)
{
  // Positive test
  LDAPCodec codec;
  const char special[] = { (char)0x28, (char)0x29, (char)0x2a, (char)0x5c, (char)0x00 };

  for( unsigned int i = 0; i < COUNTOF(special); i++ )
  {
    const string encoded = codec.encode(special, COUNTOF(special), special[i]);
    const string expected(1, special[i]);

    BOOST_CHECK((encoded == expected), "Failed to encode character");
  }
}
