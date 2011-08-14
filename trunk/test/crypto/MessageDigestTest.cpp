/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 * @author David Anderson, david.anderson@aspectsecurity.com
 */

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

// nullptr
#include <cstddef>
#include <memory>
#include <string>
using std::string;

#include "EsapiCommon.h"

// auto_ptr is deprecated in C++0X
#if defined(ESAPI_CPLUSPLUS_UNIQUE_PTR)
  using std::unique_ptr;
# define THE_AUTO_PTR  unique_ptr
#else
  using std::auto_ptr;
# define THE_AUTO_PTR  auto_ptr
#endif

#include <errors/InvalidArgumentException.h>
using esapi::InvalidArgumentException;

#include <errors/EncryptionException.h>
using esapi::EncryptionException;

#include <crypto/MessageDigest.h>
using esapi::MessageDigest;

void VerifyMessageDigest();
void VerifyArguments();
void VerifyMD5();

// Don't correct the spellin - Boost won't compile
BOOST_AUTO_TEST_CASE( VerifyMessageDiges )
{
	BOOST_MESSAGE( "Verifying MessageDigest class" );

    VerifyMessageDigest();
}

void VerifyMessageDigest()
{
	VerifyArguments();
    VerifyMD5();
}

void VerifyArguments()
{
    bool success = false;
    
	try
	{    
    	THE_AUTO_PTR<MessageDigest> md1(MessageDigest::getInstance("Foo"));
	}
    catch(InvalidArgumentException&)
    {
		success = true;
	}
	catch(EncryptionException&)
	{
	}
    BOOST_CHECK_MESSAGE(success, "Failed to catch InvalidArgumentException");

    /////////////////////////////////////////////////////////////////////////

 	THE_AUTO_PTR<MessageDigest> md2(MessageDigest::getInstance());
	success = (md2->getAlgorithm() == "SHA-256");
	BOOST_CHECK_MESSAGE(success, "Default generator " << md2->getAlgorithm() << " is unexpected");

    /////////////////////////////////////////////////////////////////////////

	try
	{    
		success = false;
    	THE_AUTO_PTR<MessageDigest> md3(MessageDigest::getInstance("MD-5"));
        md3->digest((byte*)NULL, 0, 0, 0);
	}
    catch(InvalidArgumentException&)
    {	
		success = true;
	}
	catch(EncryptionException&)
	{
	}
    BOOST_CHECK_MESSAGE(success, "Failed to throw on NULL/0 buffer (digest)");

    /////////////////////////////////////////////////////////////////////////

	try
	{    
		success = false;
    	THE_AUTO_PTR<MessageDigest> md4(MessageDigest::getInstance("MD-5"));
        byte hash[15];
        md4->digest(hash, sizeof(hash), 0, 0);        
	}
    catch(InvalidArgumentException&)
    {	
		success = true;	
	}
	catch(EncryptionException&)
	{
	}
    BOOST_CHECK_MESSAGE(success, "Failed to throw on under-sized buffer (digest)");

    /////////////////////////////////////////////////////////////////////////

	try
	{    
		success = false;
    	THE_AUTO_PTR<MessageDigest> md4(MessageDigest::getInstance("MD5"));
        volatile size_t ptr = ((size_t)-1) - 7;
        md4->digest((byte*)ptr, 64, 0, 64);
	}
    catch(InvalidArgumentException& ex)
    {
	}
	catch(EncryptionException& ex)
	{
		success = true;
	}
    BOOST_CHECK_MESSAGE(success, "Failed to throw on integer wrap (digest)");

    /////////////////////////////////////////////////////////////////////////

	try
	{    
		success = false;
    	THE_AUTO_PTR<MessageDigest> md3(MessageDigest::getInstance("MD-5"));
        md3->update((byte*)NULL, 0, 0, 0);
	}
    catch(InvalidArgumentException&)
    {	
		success = true;
	}
	catch(EncryptionException&)
	{
	}
    BOOST_CHECK_MESSAGE(success, "Failed to throw on NULL/0 buffer (update)");

    /////////////////////////////////////////////////////////////////////////

	try
	{    
		success = false;
    	THE_AUTO_PTR<MessageDigest> md4(MessageDigest::getInstance("MD5"));
        volatile size_t ptr = ((size_t)-1) - 7;
        md4->update((byte*)ptr, 64, 0, 64);
	}
    catch(InvalidArgumentException& ex)
    {
	}
	catch(EncryptionException& ex)
	{
		success = true;
	}
    BOOST_CHECK_MESSAGE(success, "Failed to throw on integer wrap (update)");

}

// http://www.ietf.org/rfc/rfc1321.txt
void VerifyMD5()
{

}

