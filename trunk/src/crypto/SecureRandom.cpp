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
*
*/

#include "EsapiCommon.h"
#include "crypto/SecureRandom.h"
#include "errors/EncryptionException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <stdexcept>

/**
* This class implements functionality similar to Java's SecureRandom for consistency
* http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html
*/
namespace esapi
{
  // Allocate storage
  SecureRandom SecureRandom::g_prng;
  std::string SecureRandom::g_name = "X9.31/AES";

  // Retrieve a reference to the global PRNG.
  SecureRandom& SecureRandom::GlobalSecureRandom()
  {
    return g_prng;
  }

  // Create an instance PRNG.
  SecureRandom::SecureRandom()
  {
    InitializeLock();
  }

  // Create an instance PRNG with a seed.
  SecureRandom::SecureRandom(const byte* seed, size_t size)
  {
    ASSERT(seed);
    ASSERT(size);

    if(!seed && size)
      throw esapi::EncryptionException("The seed array or size is not valid.");

    InitializeLock();

    AutoLock lock(m_lock);

    try
    {
      prng.IncorporateEntropy(seed, size);
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

  // Create an instance PRNG with a seed.
  SecureRandom::SecureRandom(const std::vector<byte>& seed)
  {
    ASSERT(seed.size());

    InitializeLock();

    AutoLock lock(m_lock);

    try
    {
      prng.IncorporateEntropy(&seed[0], seed.size());
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

  // Returns the name of the algorithm implemented by this SecureRandom object.
  const std::string& SecureRandom::getAlgorithm() const
  {
    ASSERT(!g_name.empty());
    return g_name;
  }

  // Generates a user-specified number of random bytes.
  void SecureRandom::nextBytes(byte* bytes, size_t size)
  {
    ASSERT(bytes);
    ASSERT(size);

    if(!bytes && size)
      throw esapi::EncryptionException("The byte array or size is not valid.");

    AutoLock lock(m_lock);

    try
    {
      prng.GenerateBlock(bytes, size);
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

  // Generates a user-specified number of random bytes.
  void SecureRandom::nextBytes(std::vector<byte>& bytes)
  {
    ASSERT(bytes.size());

    AutoLock lock(m_lock);

    try
    {
      prng.GenerateBlock(&bytes[0], bytes.size());
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

  // Reseeds this random object.
  void SecureRandom::setSeed(const byte* seed, size_t size)
  {
    ASSERT(seed);
    ASSERT(size);

    if(!seed && size)
      throw esapi::EncryptionException("The seed array or size is not valid.");

    AutoLock lock(m_lock);

    try
    {
      prng.IncorporateEntropy(seed, size);
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

  // Reseeds this random object.
  void SecureRandom::setSeed(const std::vector<byte>& seed)
  {
    ASSERT(seed.size());

    AutoLock lock(m_lock);

    try
    {
      prng.IncorporateEntropy(&seed[0], seed.size());
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

  // Reseeds this random object, using the bytes contained in the given long seed.
  void SecureRandom::setSeed(long seed)
  {
    AutoLock lock(m_lock);

    try
    {
      prng.IncorporateEntropy((const byte*)&seed, sizeof(seed));
    }
    catch(CryptoPP::Exception& e)
    {
      throw esapi::EncryptionException(std::string("Crypto++ internal error: ") + e.what());
    }
  }

#if defined(ESAPI_OS_WINDOWS)

  // Standard destructor.
  SecureRandom::~SecureRandom()
  {
    DeleteCriticalSection(&m_lock); 
  }

  // Initialize the lock for the PRNG
  void SecureRandom::InitializeLock() const
  {
    // Windows can never fail? My Arse! Bill, we need a return value.
    // http://msdn.microsoft.com/en-us/library/ms682608%28v=vs.85%29.aspx
    InitializeCriticalSection(&m_lock);
  }

  // Lock on construction
  SecureRandom::AutoLock::AutoLock(CRITICAL_SECTION& cs)
    : mm_lock(cs)
  {
    // Windows can never fail? My Arse! Bill, we need a return value.
    // http://msdn.microsoft.com/en-us/library/ms682608%28v=vs.85%29.aspx
    EnterCriticalSection(&mm_lock);
  }

  // Release on destruction
  SecureRandom::AutoLock::~AutoLock()
  {
    // Yet another function which never fails.
    LeaveCriticalSection(&mm_lock);
  }

#elif defined(ESAPI_OS_STARNIX) // ESAPI_OS_WINDOWS

  // Standard destructor.
  SecureRandom::~SecureRandom()
  {
    int ret = pthread_mutex_destroy(&m_lock);
    // ASSERT, but don't throw
    ASSERT(ret == 0);
  }

  // Initialize the lock for the PRNG
  void SecureRandom::InitializeLock() const
  {
    int ret = pthread_mutex_init(&m_lock, NULL);
    ASSERT(ret == 0);
    if(ret != 0)
    {
      std::ostringstream oss;
      oss << "Failed to intialize mutex, error = " << errno << ".";
      throw esapi::EncryptionException(oss.str());
    }
  }

  // Lock on construction
  SecureRandom::AutoLock::AutoLock(pthread_mutex_t& mtx)
    : mm_lock(mtx)
  {
    int ret = pthread_mutex_lock( &mm_lock );
    ASSERT(ret == 0);
    if(ret != 0)
    {
      std::ostringstream oss;
      oss << "Failed to acquire mutex, error = " << errno << ".";
      throw esapi::EncryptionException(oss.str());
    }
  }

  // Release on destruction
  SecureRandom::AutoLock::~AutoLock()
  {
    int ret = pthread_mutex_unlock( &mm_lock );
    ASSERT(ret == 0);
    if(ret != 0)
    {
      std::ostringstream oss;
      oss << "Failed to release mutex, error = " << errno << ".";
      throw esapi::EncryptionException(oss.str());
    }
  }
#endif // ESAPI_OS_STARNIX

} // NAMESPACE esapi
