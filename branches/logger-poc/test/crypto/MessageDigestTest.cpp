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
using std::cout;
using std::cerr;
using std::endl;

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;

#include "util/SecureArray.h"
using esapi::SecureByteArray;

#include "errors/IllegalArgumentException.h"
using esapi::IllegalArgumentException;

#include "errors/EncryptionException.h"
using esapi::EncryptionException;

#include "errors/NoSuchAlgorithmException.h"
using esapi::NoSuchAlgorithmException;

#include "crypto/MessageDigest.h"
using esapi::MessageDigest;

#include "util/TextConvert.h"
using esapi::TextConvert;

#if defined(ESAPI_OS_STARNIX)
#include <pthread.h>
#endif
#include <errno.h>

static void* WorkerThreadProc(void* param);
static void DoWorkerThreadStuff();
static const unsigned int THREAD_COUNT = 64;
static MessageDigest& SharedMessageDigest();

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_1P )
{
  bool success = false;

  try
    {    
      MessageDigest md00;
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to create digest");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_2P )
{
  bool success = false;

  try
    {    
      MessageDigest md01 = MessageDigest::getInstance();
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to create digest");
}

#if 0
BOOST_AUTO_TEST_CASE( VerifyMessageDigest_3N )
{
  bool success = false;

  try
    {    
      MessageDigest md1("Foo");
    }
  catch(esapi::NoSuchAlgorithmException&)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch NoSuchAlgorithmException");
}
#endif

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_4N )
{
  bool success = false;

  try
    {    
      MessageDigest md1("Foo");
    }
  catch(esapi::NoSuchAlgorithmException&)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch NoSuchAlgorithmException");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_5N )
{
  bool success = false;
    
  try
    {    
      MessageDigest md1(MessageDigest::getInstance("Foo"));
    }
  catch(NoSuchAlgorithmException&)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch NoSuchAlgorithmException");
}

#if 0
BOOST_AUTO_TEST_CASE( VerifyMessageDigest_6N )
{
  bool success = false;
    
  try
    {    
      MessageDigest md1(MessageDigest::getInstance("Foo"));
    }
  catch(NoSuchAlgorithmException&)
    {
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch NoSuchAlgorithmException");
}
#endif

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_7P )
{
  bool success = false;

  MessageDigest md2(MessageDigest::getInstance());
  success = (md2.getAlgorithm() == "SHA-256");
  BOOST_CHECK_MESSAGE(success, "Default generator " << md2.getAlgorithm() << " is unexpected");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_8N )
{
  bool success = false;

  try
    {
      MessageDigest md3(MessageDigest::getInstance("MD-5"));
      md3.digest((byte*)nullptr, 0, 0, 0);
    }
  catch(IllegalArgumentException&)
    {   
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on NULL/0 buffer (digest)");

}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_9N )
{
  bool success = false;

  // This throws a DigestException in Java 
  // byte[] scratch = new byte[16];
  // MessageDigest md = MessageDigest.getInstance("MD5");
  // int ret = md.digest(scratch, 0, 15);

  try
    {    
      MessageDigest md4(MessageDigest::getInstance());
      const size_t sz = md4.getDigestLength();
      SecureByteArray buf(sz);
      md4.digest(buf.data(), buf.size(), 0, sz-1);
    }
  catch(IllegalArgumentException& ex)
    {
      UNUSED_VARIABLE( ex );
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on under-sized buffer (digest)");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_10N )
{
  bool success = false;

  try
    {
      MessageDigest md5(MessageDigest::getInstance());
      size_t ptr = ((size_t)-1) - 7;
      const size_t size = md5.getDigestLength();
      md5.digest((byte*)ptr, size, 0, size);
    }
  catch(EncryptionException& ex)
    {
      UNUSED_VARIABLE( ex );
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on integer wrap (digest)");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_11N )
{
  bool success = false;

  try
    {    
      success = false;
      MessageDigest md6(MessageDigest::getInstance());
      md6.update((byte*)nullptr, 0, 0, 0);
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on NULL/0 buffer (update)");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_12N )
{
  bool success = false;

  try
    {    
      success = false;
      MessageDigest md7(MessageDigest::getInstance());
      const size_t ptr = ((size_t)-1) - 7;
      md7.update((byte*)ptr, md7.getDigestLength(), 0, 4);
    }
  catch(EncryptionException& ex)
    {
      UNUSED_VARIABLE( ex );
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on integer wrap (update)");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_13N )
{
  bool success = false;

  try
    {    
      success = false;
      MessageDigest md8(MessageDigest::getInstance());
      const size_t sz = md8.getDigestLength();
      SecureByteArray buf(sz);
      md8.digest(buf.data(), buf.size(), sz-1, 2*sz-1);
    }
  catch(IllegalArgumentException& ex)
    {
      UNUSED_VARIABLE( ex );
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on exceed bounds (digest)");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigest_14N )
{
  bool success = false;

  try
    {    
      success = false;
      MessageDigest md9(MessageDigest::getInstance());
      const size_t sz = md9.getDigestLength();
      SecureByteArray buf(sz);
      md9.update(buf.data(), buf.size(), sz-1, 2*sz-1);
    }
  catch(IllegalArgumentException& ex)
    {
      UNUSED_VARIABLE( ex );
      success = true;
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to throw on exceed bounds (update)");
}

BOOST_AUTO_TEST_CASE( VerifyMessageDigestThreads )
{
  DoWorkerThreadStuff();
}

////////////////////////////////////////////////////////////////
// MD5 test vectors: // http://www.ietf.org/rfc/rfc1321.txt    
////////////////////////////////////////////////////////////////

BOOST_AUTO_TEST_CASE( VerifyMD5_1P )
{    
  bool success = false;

  try
    {
      //MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const String msg("");
      md.update(msg);

      const byte hash[16] = {0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e};
      md.digest(buf.data(), buf.size(), 0, sz);
      success = (::memcmp(buf.data(), hash, 16) == 0);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate MD5 digest");
}

BOOST_AUTO_TEST_CASE( VerifyMD5_2P )
{    
  bool success = false;

  try
    {
      //MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const String msg("abc");
      md.update(msg);

      const byte hash[16] = {0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72};
      md.digest(buf.data(), buf.size(), 0, sz);
      success = (::memcmp(buf.data(), hash, 16) == 0);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate MD5 digest");
}

BOOST_AUTO_TEST_CASE( VerifyMD5_3P )
{    
  bool success = false;

  try
    {
      //MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const String msg("message digest");
      md.update(msg);

      const byte hash[16] = {0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0};
      md.digest(buf.data(), buf.size(), 0, sz);
      success = (::memcmp(buf.data(), hash, 16) == 0);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate MD5 digest");
}

BOOST_AUTO_TEST_CASE( VerifyMD5_4P )
{    
  bool success = false;

  try
    {
      //MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const String msg("abcdefghijklmnopqrstuvwxyz");
      md.update(msg);

      const byte hash[16] = {0xc3,0xfc,0xd3,0xd7,0x61,0x92,0xe4,0x00,0x7d,0xfb,0x49,0x6c,0xca,0x67,0xe1,0x3b};
      md.digest(buf.data(), buf.size(), 0, sz);
      success = (::memcmp(buf.data(), hash, 16) == 0);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate MD5 digest");
}

BOOST_AUTO_TEST_CASE( VerifyMD5_5P )
{    
  bool success = false;

  try
    {
      //MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") = d174ab98d277d9f5a5611c2c9f419d9f
      success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const String msg("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
      md.update(msg);

      const byte hash[16] = {0xd1,0x74,0xab,0x98,0xd2,0x77,0xd9,0xf5,0xa5,0x61,0x1c,0x2c,0x9f,0x41,0x9d,0x9f};
      md.digest(buf.data(), buf.size(), 0, sz);
      success = (::memcmp(buf.data(), hash, 16) == 0);
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
  BOOST_CHECK_MESSAGE(success, "Failed to calculate MD5 digest");
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
  MessageDigest& md = SharedMessageDigest();
  byte bytes[1024];
  
  for(unsigned int i = 0; i < 1024; i++)
    md.update(bytes, COUNTOF(bytes));

  byte digest[64];
  md.digest(digest, COUNTOF(digest), 0, md.getDigestLength());

  // Lots of trouble here. The underlying C++ standard libraries and Boost
  // make no guarantees this is valid in a multithreaded world. Despite
  // sincere efforts, we have not been able to provide it trouble free.
  // md = MessageDigest::getInstance();

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
      int ret = pthread_create(&threads[i], nullptr, WorkerThreadProc, (void*)(intptr_t)i);
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
