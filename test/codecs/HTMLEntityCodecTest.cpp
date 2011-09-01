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

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <sstream>
using std::stringstream;
using std::istringstream;
using std::ostringstream;

#include <errno.h>

#include "codecs/HTMLEntityCodec.h"
using esapi::HTMLEntityCodec;

// Some worker thread stuff
static void DoWorkerThreadStuff();
static void* WorkerThreadProc(void* param);

static const unsigned int THREAD_COUNT = 64;

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

  const char* nil = NULL;
  string encoded = codec.encodeCharacter(nil, 0, 'A');
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_5N)
{
  // Negative test
  HTMLEntityCodec codec;
  const char immune[] = { (char)0xFF };
  string encoded = codec.encodeCharacter(immune, 0, 'A');
  BOOST_CHECK_MESSAGE(encoded == string(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_6N)
{
  // Negative test
  HTMLEntityCodec codec;
  const char immune[] = { (char)0xFF };
  string encoded = codec.encodeCharacter((char*)NULL, COUNTOF(immune), 'A');
  BOOST_CHECK_MESSAGE(encoded == string(1, 'A'), "Failed to encode character");
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_7P)
{
  // Positive test
  HTMLEntityCodec codec;
  const char immune[] = { (char)0xFF };

  for( unsigned int c = 'A'; c <= 'Z'; c++)
  {
    string encoded = codec.encodeCharacter(immune, COUNTOF(immune), (char)c);
    BOOST_CHECK_MESSAGE((encoded == string(1, (char)c)), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_8P)
{
  // Positive test - uses the overload which takes a 'char' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    char c;
    string str;
  };

  // First and last 4 from entity table (below char)
  const KnownAnswer tests[] = {
    { (char)34, "&quot;" },
    { (char)38, "&amp;" },
    { (char)60, "&lt;" },
    { (char)62, "&gt;" },

    { (char)252, "&uuml;" },
    { (char)253, "&yacute;" },
    { (char)254, "&thorn;" },
    { (char)255, "&yuml;" }
  };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const string encoded = codec.encodeCharacter(NULL, 0, (char)tests[i].c);
    const string expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character " + expected);
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_9P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int c;
    string str;
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

  const char immune[] = { (char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const string encoded = codec.encodeCharacter(immune, COUNTOF(immune), tests[i].c);
    const string expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_10P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int c;
    string str;
  };

  // For companies like Apple, which has far too many lawyers
  const KnownAnswer tests[] = {    
    { 169, "&copy;" },
    { 8482, "&trade;" },
  };

  const char immune[] = { (char)0xFF };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const string encoded = codec.encodeCharacter(immune, COUNTOF(immune), tests[i].c);
    const string expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_11P)
{
  // Positive test - uses the overload which takes a 'int' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int c;
    string str;
  };

  const KnownAnswer tests[] = {    
    { 0xAAAA, "&#xaaaa;" },
    { 0xCCCC, "&#xcccc;" },
  };

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const string encoded = codec.encodeCharacter(NULL, 0, tests[i].c);
    const string expected = tests[i].str;

    BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  }
}

BOOST_AUTO_TEST_CASE(HTMLEntityCodecTest_12P)
{
  // Positive test
  //HTMLEntityCodec codec;
  //const char special[] = { (char)0x28, (char)0x29, (char)0x2a, (char)0x5c, (char)0x00 };

  //for( unsigned int i = 0; i < COUNTOF(special); i++ )
  //{
  //  const string encoded = codec.encodeCharacter(special, COUNTOF(special), special[i]);
  //  const string expected(1, special[i]);

  //  BOOST_CHECK_MESSAGE((encoded == expected), "Failed to encode character");
  //}
}

BOOST_AUTO_TEST_CASE( HTMLEntityCodecTest_13P )
{
  BOOST_MESSAGE( "Verifying HTMLEntityCodec with " << THREAD_COUNT << " threads" );

  DoWorkerThreadStuff();
}

#if defined(WIN32) || defined(_WIN32) 
void DoWorkerThreadStuff()
{
}
#elif defined(__linux) || defined(__linux__) || defined(__APPLE__)
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
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
  sleep(0);
#endif

  const std::map<int,std::string>& characterToEntityMap = HTMLEntityCodec::getCharacterToEntityMap();
  ASSERT(characterToEntityMap.size() > 0);

  BOOST_MESSAGE( " Thread " << (size_t)param << " completed" );

  return (void*)0;
}

