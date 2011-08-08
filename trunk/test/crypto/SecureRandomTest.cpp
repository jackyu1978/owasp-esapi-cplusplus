/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

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

void VerifySecureRandom()
{
    DoWorkerThreadStuff();
}

void DoWorkerThreadStuff()
{
	pthread_t threads[THREAD_COUNT];

    cout << "Testing SecureRandom with " << THREAD_COUNT << " threads" << endl;

	// *** Worker Threads ***
	for(unsigned int i=0; i<THREAD_COUNT; i++)
	{
		int ret = pthread_create(&threads[i], NULL, WorkerThreadProc, (void*)i);
		if(0 != ret /*success*/)
		{
			cerr << "pthread_create failed (thread " << i << "): " << strerror(errno) << endl;
		}
	}

	for(unsigned int i=0; i<THREAD_COUNT; i++)
	{
		int ret = pthread_join(threads[i], NULL);
		if(0 != ret /*success*/)
		{
			cerr << "pthread_join failed (thread " << i << "): " << strerror(errno) << endl;
		}
	}

    cout << "All threads completed successfully" << endl;
}

void* WorkerThreadProc(void* param)
{
	byte random[16384];

    SecureRandom prng1;
    prng1.nextBytes(random, sizeof(random));

	// give up the remainder of this time quantum to help interleave
	// thread creation between parent/child
	sleep(0);

    SecureRandom& prng2 = SecureRandom::GlobalSecureRandom();
    prng2.nextBytes(random, sizeof(random));

    cout << "  Thread " << (size_t)param << " completed" << endl;

    return (void*)0;
}

