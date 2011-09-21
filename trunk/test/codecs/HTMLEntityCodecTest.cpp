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

#define BOOST_TEST_DYN_LINK
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

#include <errno.h>

#include "codecs/HTMLEntityCodec.h"
using esapi::HTMLEntityCodec;

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

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_4N)
{
  // Negative test
  HTMLEntityCodec codec;

  const Char* nil = NULL;
  String encoded = codec.encodeCharacter(nil, 0, L'A');
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_5N)
{
  // Negative test
  HTMLEntityCodec codec;
  const Char immune[] = { (Char)0xFF };
  String encoded = codec.encodeCharacter(immune, 0, L'A');
  BOOST_CHECK_MESSAGE(encoded == String(1, L'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_6N)
{
  // Negative test
  HTMLEntityCodec codec;
  const Char immune[] = { (Char)0xFF };
  String encoded = codec.encodeCharacter((Char*)NULL, COUNTOF(immune), L'A');
  BOOST_CHECK_MESSAGE(encoded == String(1, L'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_7P)
{
  // Positive test
  HTMLEntityCodec codec;
  const Char immune[] = { (Char)0xFF };

  for( unsigned int c = L'A'; c <= L'Z'; c++)
  {
    String encoded = codec.encodeCharacter(immune, COUNTOF(immune), (Char)c);
    BOOST_CHECK_MESSAGE((encoded == String(1, (Char)c)), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_8P)
{
  // Positive test - uses the overload which takes a 'Char' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    Char c;
    String str;
  };

  // First and last 4 from entity table (below Char)
  const KnownAnswer tests[] = {
    { (Char)34, "&quot;" },
    { (Char)38, "&amp;" },
    { (Char)60, "&lt;" },
    { (Char)62, "&gt;" },

    { (Char)252, "&uuml;" },
    { (Char)253, "&yacute;" },
    { (Char)254, "&thorn;" },
    { (Char)255, "&yuml;" }
  };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const String encoded = codec.encodeCharacter(NULL, 0, (Char)tests[i].c);
    const String expected = tests[i].str;

    StringStream oss;
    oss << "Failed to encode character. Expected ";
    oss << "'" << expected << "', got ";
    oss << "'" << encoded << "'";

    BOOST_CHECK_MESSAGE((encoded == expected), oss.str());
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_9P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int c;
    String str;
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

  const Char immune[] = { (Char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const String encoded = codec.encodeCharacter(immune, COUNTOF(immune), tests[i].c);
    const String expected = tests[i].str;

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
    int c;
    String str;
  };

  // For companies like Apple, which has far too many lawyers
  const KnownAnswer tests[] = {    
    { 169, "&copy;" },
    { 8482, "&trade;" },
  };

  const Char immune[] = { (Char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const String encoded = codec.encodeCharacter(immune, COUNTOF(immune), tests[i].c);
    const String expected = tests[i].str;

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
    int c;
    String str;
  };

  const KnownAnswer tests[] = {    
    { 0xAAA, "&#x0aaa;" },
    { 0xAAAA, "&#xaaaa;" },
    { 0xCCC, "&#x0ccc;" },
    { 0xCCCC, "&#xcccc;" },
  };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const String encoded = codec.encodeCharacter(NULL, 0, tests[i].c);
    const String expected = tests[i].str;

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
  //  const String encoded = codec.encodeCharacter(special, COUNTOF(special), special[i]);
  //  const String expected(1, special[i]);

  //  StringStream oss;
  //  oss << "Failed to encode character. Expected ";
  //  oss << "'" << expected << "', got ";
  //  oss << "'" << encoded << "'";

  //  BOOST_CHECK_MESSAGE((encoded == expected), oss.str());
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
void* WorkerThreadProc(void* param)
{
}
#elif defined(ESAPI_OS_STARNIX)
void DoWorkerThreadStuff()
{
  pthread_t threads[THREAD_COUNT];

  // *** Worker Threads ***
  for(unsigned int i=0; i<THREAD_COUNT; i++)
    {
      int ret = pthread_create(&threads[i], NULL, WorkerThreadProc, (void*)i);
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
  const std::map<int,String>& characterToEntityMap = HTMLEntityCodec::getCharacterToEntityMap();
  ASSERT(characterToEntityMap.size() > 0);
#endif

  BOOST_MESSAGE( " Thread " << (size_t)param << " completed" );

  return (void*)0;
}


