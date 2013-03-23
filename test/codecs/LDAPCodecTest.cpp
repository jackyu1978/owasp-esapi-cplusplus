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

#include <iostream>
#include <iomanip>
using std::cout;
using std::cerr;
using std::endl;

#include "EsapiCommon.h"
using esapi::Char;
using esapi::WideString;
using esapi::NarrowString;
using esapi::StringStream;
using esapi::StringArray;

#include <codecs/LDAPCodec.h>
using esapi::LDAPCodec;

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
  StringArray immune;

  NarrowString encoded = codec.encodeCharacter(immune, "A");
  BOOST_CHECK_MESSAGE(encoded == NarrowString(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_5N)
{
  // Negative test
  LDAPCodec codec;
  StringArray immune;
  immune.push_back("");

  NarrowString encoded = codec.encodeCharacter(immune, "A");
  BOOST_CHECK_MESSAGE(encoded == NarrowString(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_6N)
{
  // Negative test
  LDAPCodec codec;
  StringArray immune;
  immune.push_back("\xFF");

  NarrowString encoded = codec.encodeCharacter(immune, "A");
  BOOST_CHECK_MESSAGE(encoded == NarrowString(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_7P)
{
  // Positive test
  LDAPCodec codec;
  StringArray immune;
  immune.push_back("\xFF");

  for( unsigned int c = 'A'; c <= 'Z'; c++)
  {
    NarrowString encoded = codec.encodeCharacter(immune, NarrowString(1,(char)c));
    BOOST_CHECK_MESSAGE((encoded == NarrowString(1,(char)c)), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_8P)
{
  // Positive test
  LDAPCodec codec;

  struct KnownAnswer
  {
    Char c;
    NarrowString str;
  };

  const KnownAnswer tests[] = {
    { (Char)'\\', "\\5c" },
    { (Char)'*', "\\2a" },
    { (Char)'(', "\\28" },
    { (Char)')', "\\29" },
    { (Char)'\0', "\\00" },
  };

  StringArray immune;
  immune.push_back("\xFF");

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const NarrowString encoded = codec.encodeCharacter(immune, NarrowString(1,tests[i].c));
    const NarrowString expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_9P)
{
  // Positive test
  LDAPCodec codec;
  StringArray special;

  special.push_back("\x28");
  special.push_back("\x29");
  special.push_back("\x2a");
  special.push_back("\x5c");
  special.push_back("\x00");

  for( unsigned int i = 0; i < special.size(); i++ )
  {
    const NarrowString encoded = codec.encodeCharacter(special, special[i]);
    const NarrowString expected(special[i]);

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

