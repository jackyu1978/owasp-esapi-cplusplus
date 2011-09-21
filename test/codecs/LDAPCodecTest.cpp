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
#include <iomanip>
using std::cout;
using std::cerr;
using std::endl;

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"
#include <codecs/LDAPCodec.h>
using esapi::LDAPCodec;

#include <string>
#include <sstream>
using String;
using std::ostringstream;

#define HEX(x) std::hex << std::setw(x) << std::setfill('0')
#define OCT(x) std::octal << std::setw(x) << std::setfill('0')

static const unsigned int THREAD_COUNT = 64;

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

  const Char* nil = NULL;
  string encoded = codec.encodeCharacter(nil, 0, 'A');
  BOOST_CHECK_MESSAGE(encoded == string(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_5N)
{
  // Negative test
  LDAPCodec codec;
  const Char immune[] = { (Char)0xFF };
  string encoded = codec.encodeCharacter(immune, 0, 'A');
  BOOST_CHECK_MESSAGE(encoded == string(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_6N)
{
  // Negative test
  LDAPCodec codec;
  const Char immune[] = { (Char)0xFF };
  string encoded = codec.encodeCharacter((Char*)NULL, COUNTOF(immune), 'A');
  BOOST_CHECK_MESSAGE(encoded == string(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_7P)
{
  // Positive test
  LDAPCodec codec;
  const Char immune[] = { (Char)0xFF };

  for( unsigned int c = 'A'; c <= 'Z'; c++)
  {
    string encoded = codec.encodeCharacter(immune, COUNTOF(immune), (Char)c);
    BOOST_CHECK_MESSAGE((encoded == string(1, (Char)c)), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_8P)
{
  // Positive test
  LDAPCodec codec;

  struct KnownAnswer
  {
    Char c;
    string str;
  };

  const KnownAnswer tests[] = {
    { (Char)'\\', "\\5c" },
    { (Char)'*', "\\2a" },
    { (Char)'(', "\\28" },
    { (Char)')', "\\29" },
    { (Char)'\0', "\\00" },
  };

  const Char immune[] = { (Char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const string encoded = codec.encodeCharacter(immune, COUNTOF(immune), tests[i].c);
    const string expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_9P)
{
  // Positive test
  LDAPCodec codec;
  const Char special[] = { (Char)0x28, (Char)0x29, (Char)0x2a, (Char)0x5c, (Char)0x00 };

  for( unsigned int i = 0; i < COUNTOF(special); i++ )
  {
    const string encoded = codec.encodeCharacter(special, COUNTOF(special), special[i]);
    const string expected(1, special[i]);

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

