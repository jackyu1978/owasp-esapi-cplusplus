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
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
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

#include "EsapiCommon.h"
using esapi::NarrowString;
using esapi::WideString;
using esapi::StringArray;
using esapi::StringStream;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <errno.h>

#include "codecs/HTMLEntityCodec.h"
using esapi::HTMLEntityCodec;

#include "util/TextConvert.h"
using esapi::TextConvert;

static const unsigned int THREAD_COUNT = 64;
static void DoWorkerThreadStuff();
static void* WorkerThreadProc(void* param);


BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_1P)
{
  // Positive test - construction
  HTMLEntityCodec codec;
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_2P)
{
  // Positive test - copy
  HTMLEntityCodec codec1;
  HTMLEntityCodec codec2(codec1);
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_3P)
{
  // Positive test - assignment
  HTMLEntityCodec codec1;
  HTMLEntityCodec codec2 = codec1;
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_4P)
{
  // Positive test
  HTMLEntityCodec codec;
  StringArray immune;

  NarrowString encoded = codec.encodeCharacter(immune, "A");
  BOOST_CHECK_MESSAGE(encoded == "A", "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_5P)
{
  // Positive test
  HTMLEntityCodec codec;
  StringArray immune;
  immune.push_back("\xFF");

  NarrowString encoded = codec.encodeCharacter(immune, "A");
  BOOST_CHECK_MESSAGE(encoded == "A", "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_6P)
{
  // Positive test
  HTMLEntityCodec codec;
  StringArray immune;
  immune.push_back("\xFF");

  for( unsigned int c = 'a'; c <= 'z'; c++)
  {
    NarrowString encoded = codec.encodeCharacter(immune, NarrowString(1, static_cast<char>(c)));
    BOOST_CHECK_MESSAGE((encoded == NarrowString(1, static_cast<char>(c))), "Failed to encode character");
  }

    for( unsigned int c = 'A'; c <= 'Z'; c++)
  {
    NarrowString encoded = codec.encodeCharacter(immune, NarrowString(1, static_cast<char>(c)));
    BOOST_CHECK_MESSAGE((encoded == NarrowString(1, static_cast<char>(c))), "Failed to encode character");
  }

      for( unsigned int c = '0'; c <= '9'; c++)
  {
    NarrowString encoded = codec.encodeCharacter(immune, NarrowString(1, static_cast<char>(c)));
    BOOST_CHECK_MESSAGE((encoded == NarrowString(1, static_cast<char>(c))), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_7P)
{
  // Positive test - uses the overload which takes a 'Char' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int ch;
    NarrowString str;
  };

  // First and last 4 from entity table
  const KnownAnswer tests[] = {
    { 34, "&quot;" },
    { 38, "&amp;" },
    { 60, "&lt;" },
    { 62, "&gt;" },

    { 252, "&uuml;" },
    { 253, "&yacute;" },
    { 254, "&thorn;" },
    { 255, "&yuml;" }
  };

  StringArray immune;

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const NarrowString utf8 = TextConvert::WideToNarrow(WideString(1,tests[i].ch));
    const NarrowString encoded = codec.encodeCharacter( immune, utf8 );
    const NarrowString expected = tests[i].str;

    StringStream oss;
    oss << "Failed to encode character. Expected ";
    oss << "'" << expected << "', got ";
    oss << "'" << encoded << "'";

    BOOST_CHECK_MESSAGE((encoded == expected), oss.str());
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_8P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int ch;
    NarrowString str;
  };

  // First, middle, and last 4 from entity table
  const KnownAnswer tests[] = {
    { 34, "&quot;" },
    { 38, "&amp;" },
    { 60, "&lt;" },
    { 62, "&gt;" },

    { 929, "&Rho;" },
    { 931, "&Sigma;" },
    { 932, "&Tau;" },
    { 933, "&Upsilon;" },

    { 9824, "&spades;" },
    { 9827, "&clubs;" },
    { 9829, "&hearts;" },
    { 9830, "&diams;" }
  };

  StringArray immune;
  immune.push_back("\xFF");

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const NarrowString utf8 = TextConvert::WideToNarrow(WideString(1,tests[i].ch));
    const NarrowString encoded = codec.encodeCharacter( immune, utf8 );
    const NarrowString expected = tests[i].str;

    StringStream oss;
    oss << "Failed to encode character. Expected ";
    oss << "'" << expected << "', got ";
    oss << "'" << encoded << "'";

    BOOST_CHECK_MESSAGE((encoded == expected), oss.str());
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_10P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int ch;
    NarrowString str;
  };

  // For companies like Apple, which has far too many lawyers
  const KnownAnswer tests[] = {    
    { 169, "&copy;" },
    { 8482, "&trade;" },
  };

  StringArray immune;
  immune.push_back("\xFF");

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const NarrowString utf8 = TextConvert::WideToNarrow(WideString(1,tests[i].ch));
    const NarrowString encoded = codec.encodeCharacter( immune, utf8 );
    const NarrowString expected = tests[i].str;

    StringStream oss;
    oss << "Failed to encode character. Expected ";
    oss << "'" << expected << "', got ";
    oss << "'" << encoded << "'";

    BOOST_CHECK_MESSAGE((encoded == expected), oss.str());
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_11P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int ch;
    NarrowString str;
  };

  const KnownAnswer tests[] = {    
    { 0xAAA, "&#x0aaa;" },
    { 0xAAAA, "&#xaaaa;" },
    { 0xCCC, "&#x0ccc;" },
    { 0xCCCC, "&#xcccc;" },
  };

  StringArray immune;
  immune.push_back("\xFF");

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const NarrowString encoded = codec.encodeCharacter( immune, NarrowString(1,tests[i].ch) );
    const NarrowString expected = tests[i].str;

    StringStream oss;
    oss << "Failed to encode character. Expected ";
    oss << "'" << expected << "', got ";
    oss << "'" << encoded << "'";

    BOOST_CHECK_MESSAGE((encoded == expected), oss.str());
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_12P)
{
  // Positive test
  //HTMLEntityCodec codec;
  //const Char special[] = { (Char)0x28, (Char)0x29, (Char)0x2a, (Char)0x5c, (Char)0x00 };

  //for( unsigned int i = 0; i < COUNTOF(special); i++ )
  //{
  //  const NarrowString encoded = codec.encodeCharacter(special, COUNTOF(special), special[i]);
  //  const NarrowString expected(1, special[i]);

  //  StringStream oss;
  //  oss << "Failed to encode character. Expected ";
  //  oss << "'" << expected << "', got ";
  //  oss << "'" << encoded << "'";

  //  BOOST_CHECK_MESSAGE((encoded == expected), TextConvert::WideToNarrow(oss.str()));
  //}
}

BOOST_AUTO_TEST_CASE( HTMLEntityCodecTest_13P )
{
  BOOST_MESSAGE( "Verifying HTMLEntityCodec with " << THREAD_COUNT << " threads" );

  DoWorkerThreadStuff();
}

// Some worker thread stuff
#if defined(WIN32) || defined(_WIN32) 
void DoWorkerThreadStuff()
{
}
#elif defined(ESAPI_OS_STARNIX)
void DoWorkerThreadStuff()
{
  pthread_t threads[THREAD_COUNT];

  // *** Worker Threads ***
  for(unsigned int i=0; i<THREAD_COUNT; i++)
    {
      int ret = pthread_create(&threads[i], NULL, WorkerThreadProc, (void*)(intptr_t)i);
      if(0 != ret /*success*/)
        {
          BOOST_ERROR( "pthread_create failed (thread " << i << "): " << strerror(errno) );
        }
    }

  for(unsigned int i=0; i<THREAD_COUNT; i++)
    {
      int ret = pthread_join(threads[i], NULL);
      if(0 != ret /*success*/)
        {
          BOOST_ERROR( "pthread_join failed (thread " << i << "): " << strerror(errno) );
        }
    }

  BOOST_MESSAGE( " All threads completed successfully" );
}
#endif

void* WorkerThreadProc(void* param)
{
  // give up the remainder of this time quantum to help
  // interleave thread creation and execution
#if defined(WIN32) || defined(_WIN32)
  Sleep(0);
#elif defined(ESAPI_OS_STARNIX)
  sleep(0);
#endif

#if !defined(ESAPI_BUILD_RELEASE)
  const std::map<Char,String>& characterToEntityMap = HTMLEntityCodec::getCharacterToEntityMap();
  ASSERT(characterToEntityMap.size() > 0);
#endif

  BOOST_MESSAGE( " Thread " << (size_t)param << " completed" );

  return (void*)0;
}


