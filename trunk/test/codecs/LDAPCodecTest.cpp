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
using esapi::String;
using esapi::StringStream;

#include <codecs/LDAPCodec.h>
using esapi::LDAPCodec;

#define HEX(x) std::hex << std::setw(x) << std::setfill(L'0')
#define OCT(x) std::octal << std::setw(x) << std::setfill(L'0')

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
  String encoded = codec.encodeCharacter(nil, 0, L'A');
  BOOST_CHECK_MESSAGE(encoded == String(1, L'A'), L"Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_5N)
{
  // Negative test
  LDAPCodec codec;
  const Char immune[] = { (Char)0xFF };
  String encoded = codec.encodeCharacter(immune, 0, L'A');
  BOOST_CHECK_MESSAGE(encoded == String(1, L'A'), L"Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_6N)
{
  // Negative test
  LDAPCodec codec;
  const Char immune[] = { (Char)0xFF };
  String encoded = codec.encodeCharacter((Char*)NULL, COUNTOF(immune), L'A');
  BOOST_CHECK_MESSAGE(encoded == String(1, L'A'), L"Failed to encode character");
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_7P)
{
  // Positive test
  LDAPCodec codec;
  const Char immune[] = { (Char)0xFF };

  for( unsigned int c = L'A'; c <= L'Z'; c++)
  {
    String encoded = codec.encodeCharacter(immune, COUNTOF(immune), (Char)c);
    BOOST_CHECK_MESSAGE((encoded == String(1, (Char)c)), L"Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_8P)
{
  // Positive test
  LDAPCodec codec;

  struct KnownAnswer
  {
    Char c;
    String str;
  };

  const KnownAnswer tests[] = {
    { (Char)'\\', L"\\5c" },
    { (Char)'*', L"\\2a" },
    { (Char)'(', L"\\28" },
    { (Char)')', L"\\29" },
    { (Char)'\0', L"\\00" },
  };

  const Char immune[] = { (Char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const String encoded = codec.encodeCharacter(immune, COUNTOF(immune), tests[i].c);
    const String expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), L"Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(LDAPCodecTest_9P)
{
  // Positive test
  LDAPCodec codec;
  const Char special[] = { (Char)0x28, (Char)0x29, (Char)0x2a, (Char)0x5c, (Char)0x00 };

  for( unsigned int i = 0; i < COUNTOF(special); i++ )
  {
    const String encoded = codec.encodeCharacter(special, COUNTOF(special), special[i]);
    const String expected(1, special[i]);

    BOOST_CHECK_MESSAGE((encoded == expected), L"Failed to encode character");
  }
}

