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
#include "crypto/SecretKey.h"

#pragma once

#include <string>
#include <vector>

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

// Crypto++ is MT safe at the class level, meaning it does not share data amoung
// instances. If a Global PRNG is provided, we must take care to ensure only one 
// thread is operating on it at a time since there's only one set of data within
// the class (ie, there is no thread local storage). So far, we only support
// Windows, Linux, and Apple.
#if !defined(ESAPI_OS_WINDOWS) && !defined(ESAPI_OS_STARNIX)
# error "Unsupported operating system platform"
#endif

#if defined(ESAPI_OS_WINDOWS)
# include <windows.h>
#endif

#if defined(ESAPI_OS_STARNIX)
# include <pthread.h>
# include <errno.h>
#endif

namespace esapi
{
  /**
   * This class implements functionality similar to Java's SecureRandom for consistency
   * http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html
   */
  class SecureRandom
  {
  public:
    // Retrieve a reference to the global PRNG.
    static SecureRandom& GlobalSecureRandom();

    // Create an instance PRNG.
    explicit SecureRandom();

    // Create an instance PRNG with a seed.
    explicit SecureRandom(const byte* seed, size_t size);

    // Create an instance PRNG with a seed.
    explicit SecureRandom(const std::vector<byte>& seed);

    // Standard destructor.
    virtual ~SecureRandom();

    // Returns the name of the algorithm implemented by this SecureRandom object.
    virtual const std::string& getAlgorithm() const;

    // Generates a user-specified number of random bytes.
    void nextBytes(byte* bytes, size_t size);   

    // Generates a user-specified number of random bytes.
    void nextBytes(std::vector<byte>& bytes);

    // Reseeds this random object.
    void setSeed(const byte* seed, size_t size);

    // Reseeds this random object.
    void setSeed(const std::vector<byte>& seed);
      
    // Reseeds this random object, using the bytes contained in the given long seed.
    void setSeed(long seed);

  protected:

    // Initialize the lock for the PRNG
    inline void InitializeLock() const;

    class AutoLock
    {
#if defined(ESAPI_OS_WINDOWS)
    public:
      explicit AutoLock(CRITICAL_SECTION& cs);
      virtual ~AutoLock();
    private:
      CRITICAL_SECTION& mm_lock;
#elif defined(ESAPI_OS_STARNIX)
    public:
      explicit AutoLock(pthread_mutex_t& mtx);
      virtual ~AutoLock();
    private:
      pthread_mutex_t& mm_lock;
#endif        
    };

  private:
    // A instance PRNG
    CryptoPP::AutoSeededX917RNG<CryptoPP::AES> prng;	

    // A global PRNG
    static SecureRandom g_prng;
	static std::string g_name; // `prng` returns "unknown"

    // Crypto++ is MT safe at the class level, meaning it does not share data amoung
    // instances. If a Global PRNG is provided, we must take care to ensure only one 
    // thread is operating on it at a time since there's only one set of data within
    // the class (ie, there is no thread local storage).
#if defined(ESAPI_OS_WINDOWS)
    mutable CRITICAL_SECTION m_lock;
#elif defined(ESAPI_OS_STARNIX)
    mutable pthread_mutex_t m_lock;
#endif

  };

}; // NAMESPACE esapi

