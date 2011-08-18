/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 * @author David Anderson, david.anderson@aspectsecurity.com
 *
 */

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"

// auto_ptr is deprecated in C++0X
#if defined(ESAPI_CPLUSPLUS_UNIQUE_PTR)
# define THE_AUTO_PTR  std::unique_ptr
#else
# define THE_AUTO_PTR  std::auto_ptr
#endif

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

#include <crypto/SecureRandom.h>
using esapi::SecureRandom;

// Some worker thread stuff
void DoWorkerThreadStuff();
void* WorkerThreadProc(void* param);

static const unsigned int THREAD_COUNT = 64;

BOOST_AUTO_TEST_CASE( VerifySecureRandom )
{
  BOOST_MESSAGE( "Verifying SecureRandom with " << THREAD_COUNT << " threads" );

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
  byte random[8192];

  SecureRandom prng1;
  for (unsigned int i = 0; i < 64; i++)
    prng1.nextBytes(random, i+1);

  prng1.nextBytes(random, sizeof(random));

  // give up the remainder of this time quantum to help
  // interleave thread creation and execution
#if defined(WIN32) || defined(_WIN32) 
  Sleep(0);
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
  sleep(0);
#endif

  SecureRandom& prng2 = SecureRandom::GlobalSecureRandom();
  prng2.nextBytes(random, sizeof(random));

  for (unsigned int i = 0; i < 64; i++)
    prng2.setSeed(random, i+8);

  BOOST_MESSAGE( " Thread " << (size_t)param << " completed" );

  return (void*)0;
}

