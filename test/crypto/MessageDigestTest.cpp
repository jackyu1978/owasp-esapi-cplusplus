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
using esapi::SecureByteArray;

#include <errors/InvalidArgumentException.h>
using esapi::InvalidArgumentException;

#include <errors/EncryptionException.h>
using esapi::EncryptionException;

#include <crypto/MessageDigest.h>
using esapi::MessageDigest;

#include <pthread.h>

static void* WorkerThreadProc(void* param);
static void DoWorkerThreadStuff();
static const unsigned int THREAD_COUNT = 64;
static MessageDigest& SharedMessageDigest();

BOOST_AUTO_TEST_CASE( VerifyMessageDigestArguments )
{
  bool success = false;

  try
    {    
      MessageDigest md1("Foo");
    }
  catch(InvalidArgumentException&)
    {
      success = true;
    }
  catch(EncryptionException&)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch InvalidArgumentException");

  /////////////////////////////////////////////////////////////////////////
    
  try
    {    
      MessageDigest md1(MessageDigest::getInstance("Foo"));
    }
  catch(InvalidArgumentException&)
    {
      success = true;
    }
  catch(EncryptionException&)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch InvalidArgumentException");

  /////////////////////////////////////////////////////////////////////////

  MessageDigest md2(MessageDigest::getInstance());
  success = (md2.getAlgorithm() == "SHA-256");
  BOOST_CHECK_MESSAGE(success, "Default generator " << md2.getAlgorithm() << " is unexpected");

  /////////////////////////////////////////////////////////////////////////

  try
    {    
      success = false;
      MessageDigest md3(MessageDigest::getInstance("MD-5"));
      md3.digest((byte*)nullptr, 0, 0, 0);
    }
  catch(InvalidArgumentException&)
    {   
      success = true;
    }
  catch(EncryptionException&)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on NULL/0 buffer (digest)");

  /////////////////////////////////////////////////////////////////////////

  // This throws a DigestException in Java 
  // byte[] scratch = new byte[16];
  // MessageDigest md = MessageDigest.getInstance("MD5");
  // int ret = md.digest(scratch, 0, 15);

  try
    {    
      success = false;
      MessageDigest md4(MessageDigest::getInstance());
      const size_t sz = md4.getDigestLength();
      SecureByteArray buf(sz);
      md4.digest(&buf[0], buf.size(), 0, sz-1);
    }
  catch(InvalidArgumentException& ex)
    {
      success = true;
    }
  catch(EncryptionException& ex)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on under-sized buffer (digest)");

  /////////////////////////////////////////////////////////////////////////

  try
    {    
      success = false;
      MessageDigest md5(MessageDigest::getInstance());
      size_t ptr = ((size_t)-1) - 7;
      const size_t size = md5.getDigestLength();
      md5.digest((byte*)ptr, size, 0, size);
    }
  catch(InvalidArgumentException& ex)
    {
      cerr << "!!Caught InvalidArgumentException" << endl;
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
      MessageDigest md6(MessageDigest::getInstance());
      md6.update((byte*)nullptr, 0, 0, 0);
    }
  catch(InvalidArgumentException&)
    {   
      success = true;
    }
  catch(EncryptionException&)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on NULL/0 buffer (update)");

  /////////////////////////////////////////////////////////////////////////

  try
    {    
      success = false;
      MessageDigest md7(MessageDigest::getInstance());
      const size_t ptr = ((size_t)-1) - 7;
      md7.update((byte*)ptr, md7.getDigestLength(), 0, 4);
    }
  catch(InvalidArgumentException& ex)
    {
      cerr << "!!Caught InvalidArgumentException" << endl;
    }
  catch(EncryptionException& ex)
    {
      success = true;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on integer wrap (update)");

  /////////////////////////////////////////////////////////////////////////

  try
    {    
      success = false;
      MessageDigest md8(MessageDigest::getInstance());
      const size_t sz = md8.getDigestLength();
      SecureByteArray buf(sz);
      md8.digest(&buf[0], buf.size(), sz-1, 2*sz-1);
    }
  catch(InvalidArgumentException& ex)
    {
      success = true;
    }
  catch(EncryptionException& ex)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on exceed bounds (digest)");

  /////////////////////////////////////////////////////////////////////////

  try
    {    
      success = false;
      MessageDigest md9(MessageDigest::getInstance());
      const size_t sz = md9.getDigestLength();
      SecureByteArray buf(sz);
      md9.update(&buf[0], buf.size(), sz-1, 2*sz-1);
    }
  catch(InvalidArgumentException& ex)
    {
      success = true;
    }
  catch(EncryptionException& ex)
    {
      cerr << "!!Caught EncryptionException" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on exceed bounds (update)");

}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestThreads )
{
  DoWorkerThreadStuff();
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestMD5 )
{
  // http://www.ietf.org/rfc/rfc1321.txt
        
  //MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
  //MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
  //MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
  //MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
  //MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f
  //MD5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890") = 57edf4a22be3c955ac49da2e2107b67a

  bool success = false;

  try
    {
      //MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const string msg("");
      md.update((const byte*)msg.data(), msg.size());

      const byte hash[16] = {0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e};
      md.digest(&buf[0], buf.size(), 0, sz);
      success = (::memcmp(&buf[0], hash, 16) == 0);
    }
  catch(...)
    {

    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate hash (1)");

  /////////////////////////////////////////////////////////////////////////

  try
    {
      //MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const string msg("abc");
      md.update((const byte*)msg.data(), msg.size());

      const byte hash[16] = {0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72};
      md.digest(&buf[0], buf.size(), 0, sz);
      success = (::memcmp(&buf[0], hash, 16) == 0);
    }
  catch(...)
    {

    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate hash (2)");

  /////////////////////////////////////////////////////////////////////////

  try
    {
      //MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const string msg("message digest");
      md.update((const byte*)msg.data(), msg.size());

      const byte hash[16] = {0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0};
      md.digest(&buf[0], buf.size(), 0, sz);
      success = (::memcmp(&buf[0], hash, 16) == 0);
    }
  catch(...)
    {

    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate hash (3)");

  /////////////////////////////////////////////////////////////////////////

  try
    {
      //MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const string msg("abcdefghijklmnopqrstuvwxyz");
      md.update((const byte*)msg.data(), msg.size());

      const byte hash[16] = {0xc3,0xfc,0xd3,0xd7,0x61,0x92,0xe4,0x00,0x7d,0xfb,0x49,0x6c,0xca,0x67,0xe1,0x3b};
      md.digest(&buf[0], buf.size(), 0, sz);
      success = (::memcmp(&buf[0], hash, 16) == 0);
    }
  catch(...)
    {

    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate hash (4)");

  /////////////////////////////////////////////////////////////////////////

  try
    {
      //MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const string msg("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
      md.update((const byte*)msg.data(), msg.size());

      const byte hash[16] = {0xd1,0x74,0xab,0x98,0xd2,0x77,0xd9,0xf5,0xa5,0x61,0x1c,0x2c,0x9f,0x41,0x9d,0x9f};
      md.digest(&buf[0], buf.size(), 0, sz);
      success = (::memcmp(&buf[0], hash, 16) == 0);
    }
  catch(...)
    {

    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate hash (4)");

}

/*
BOOST_AUTO_TEST_CASE( VerifyMessageDigestSHA1 )
{
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestSHA224 )
{
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestSHA256 )
{
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestSHA384 )
{
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestSHA512 )
{
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestWhirlpool )
{
}
*/

MessageDigest& SharedMessageDigest()
{
  static MessageDigest s_md;
  return s_md;
}

void* WorkerThreadProc(void* param)
{
  byte bytes[1024];
  MessageDigest& md = SharedMessageDigest();
  
  for(unsigned int i = 0; i < 1024; i++)
    md.update(bytes, COUNTOF(bytes));

  bytes digest[64];
  md.digest(digest, COUNTOF(digest));

  BOOST_MESSAGE( "Thread " << (size_t)param << " completed" );

  return (void*)0;
}

#if defined(ESAPI_OS_WINDOWS) 
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
      int ret = pthread_create(&threads[i], nullptr, WorkerThreadProc, (void*)i);
      if(0 != ret /*success*/)
        {
          BOOST_ERROR( "pthread_create failed (thread " << i << "): " << strerror(errno) );
        }
    }

  for(unsigned int i=0; i<THREAD_COUNT; i++)
    {
      int ret = pthread_join(threads[i], nullptr);
      if(0 != ret /*success*/)
        {
          BOOST_ERROR( "pthread_join failed (thread " << i << "): " << strerror(errno) );
        }
    }

  BOOST_MESSAGE( "All threads completed successfully" );
}
#endif

