/**
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

#include "crypto/SecureRandom.h"
#include "crypto/SecureRandomImpl.h"
#include "crypto/Crypto++Common.h"
#include "safeint/SafeInt3.hpp"

#include <algorithm>

/**
 * This class implements functionality similar to Java's SecureRandom for consistency
 * http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html
 */
namespace esapi
{
  /**
   * The default secure random number generator (RNG) algorithm. Currently returns
   * SHA-256. SHA-1 is approved for Random Number Generation. See SP 800-57, Table 2.
   */
  String SecureRandom::DefaultAlgorithm()
  {
    return String(L"SHA-256");
  }

  /**
   * Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
   */
  SecureRandom SecureRandom::getInstance(const String& algorithm)
   
  {
    ASSERT( !algorithm.empty() );

    const String alg(normalizeAlgortihm(algorithm));
    SecureRandomImpl* impl = SecureRandomImpl::createInstance(alg, nullptr, 0);
    MEMORY_BARRIER();

    ASSERT(impl != nullptr);
    if(impl == nullptr)
      throw EncryptionException("Failed to create SecureRandom");

    return SecureRandom(impl);
  }

  /**
   * Constructs a secure random number generator (RNG) implementing the named
   * random number algorithm if specified
   */
  SecureRandom::SecureRandom(const String& algorithm)
   
    : m_lock(new Mutex), m_impl(SecureRandomImpl::createInstance(normalizeAlgortihm(algorithm), nullptr, 0))    
  {
    ASSERT( !algorithm.empty() );
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to create SecureRandom");
  }

  /**
   * Constructs a secure random number generator (RNG) implementing the default random number algorithm.
   */
  SecureRandom::SecureRandom(const byte seed[], size_t size)
   
    : m_lock(new Mutex), m_impl(SecureRandomImpl::createInstance(DefaultAlgorithm(), seed, size))
  {
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to create SecureRandom");
  }

  /**
   * Constructs a secure random number generator (RNG) from a SecureRandomImpl implementation.
   */
  SecureRandom::SecureRandom(SecureRandomImpl* impl)
   
    : m_lock(new Mutex), m_impl(impl)
  {
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to create SecureRandom");
  }

  /**
   * Copy this secure random number generator (RNG).
   */
  SecureRandom::SecureRandom(const SecureRandom& rhs)
    : m_lock(rhs.m_lock), m_impl(rhs.m_impl)
  {
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);
  }

  /**
   * Assign this secure random number generator (RNG).
   */
  SecureRandom& SecureRandom::operator=(const SecureRandom& rhs)
  {
    // Need to think about this one.... We want to lock 'this' in case
    // someone else is using it. However, MutexLock takes a reference
    // to 'this' object's lock. After the assignment below, the lock
    // has changed (it points to the new object lock). We subsequently
    // release the new lock (not the old lock).
    //boost::shared_ptr<Mutex> tlock(m_lock);
    //ASSERT(tlock.get() != nullptr);
    //MutexLock lock(*tlock.get());

    if(this != &rhs)
    {
      m_lock = rhs.m_lock;
      m_impl = rhs.m_impl;
    }

    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    return *this;
  }

  /**
   * Retrieves the object level lock
   */
  Mutex& SecureRandom::getObjectLock() const
  {
    ASSERT(m_lock.get());
    return *m_lock.get();
  }

  /**
   * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
   */
  SecureByteArray SecureRandom::generateSeed(unsigned int numBytes)
   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    return m_impl->generateSeedImpl(numBytes);
  }

  /**
   * Returns the name of the algorithm implemented by this SecureRandom object.
   */
  String SecureRandom::getAlgorithm() const
   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    return m_impl->getAlgorithmImpl();
  }  

  /**
   * Returns the security level associated with the SecureRandom object. Used
   * by KeyGenerator to determine the appropriate key size for init.
   */
  unsigned int SecureRandom::getSecurityLevel() const
   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve security level");

    return m_impl->getSecurityLevelImpl();
  }

  /**
   * Generates a user-specified number of random bytes.
   */
  void SecureRandom::nextBytes(byte bytes[], size_t size)
   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to generate random bytes");

    m_impl->nextBytesImpl(bytes, size);
  }

  /**
   * Reseeds this random object.
   */
  void SecureRandom::setSeed(const byte seed[], size_t size)
   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to seed the generator");

    // No need to lock - RandomPool provides its own
    RandomPool::GetSharedInstance().Reseed();

    // Reseed the SecureRandom object
    m_impl->setSeedImpl(seed, size);
  }

  /**
   * Reseeds this random object, using the bytes contained in the given long seed.
   */
  void SecureRandom::setSeed(int seed)
   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to seed the generator");

    m_impl->setSeedImpl((const byte*)&seed, sizeof(seed));
  }

  /**
   * Normalizes the algorithm name. An empty string on input is interpreted as
   * the default algortihm. If the algorithm is not found (ie, unsupported),
   * return the empty string.
   */
  String SecureRandom::normalizeAlgortihm(const String& algorithm)
  {
    ASSERT(!algorithm.empty());

    String alg(algorithm), mode;
    String::size_type pos;

    // Cut out whitespace
    String::iterator it = std::remove_if(alg.begin(), alg.end(), ::isspace);
    if(it != alg.end())
      alg.erase(it, alg.end());

    String trimmed(alg);

    // Normalize the case
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    // Normalize the slashes (we expect forward slashes, not back slashes)
    while(String::npos != (pos = alg.find(L'\\')))
      alg.replace(pos, 1, L"/");

    // Split the string between CIPHER/MODE. Note that there might also be padding, but we ignore it
    if(String::npos != (pos = alg.find(L'/')))
      {
        mode = alg.substr(pos+1);
        alg.erase(pos);
      }

    // Lop off anything remaining in the mode such as padding - we always use Crypto++ default padding
    if(String::npos != (pos = mode.find(L'/')))
      mode.erase(pos);

    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html

    ////////////////////////////////// Block Ciphers //////////////////////////////////

    if(alg == L"aes" && mode.empty())
      return L"AES";

    if(alg == L"aes" && mode == L"cfb")
      return L"AES/CFB";

    if(alg == L"aes" && mode == L"ofb")
      return L"AES/OFB";

    if(alg == L"aes" && mode == L"ctr")
      return L"AES/CTR";

    if((alg == L"aes128" || alg == L"aes-128") && mode == L"")
      return L"AES128";

    if((alg == L"aes128" || alg == L"aes-128") && mode == L"cfb")
      return L"AES128/CFB";

    if((alg == L"aes128" || alg == L"aes-128") && mode == L"ofb")
      return L"AES128/OFB";

    if((alg == L"aes128" || alg == L"aes-128") && mode == L"ctr")
      return L"AES128/CTR";

    if((alg == L"aes192" || alg == L"aes-192") && mode == L"")
      return L"AES192";

    if((alg == L"aes192" || alg == L"aes-192") && mode == L"cfb")
      return L"AES192/CFB";

    if((alg == L"aes192" || alg == L"aes-192") && mode == L"ofb")
      return L"AES192/OFB";

    if((alg == L"aes192" || alg == L"aes-192") && mode == L"ctr")
      return L"AES192/CTR";

    if((alg == L"aes256" || alg == L"aes-256") && mode == L"")
      return L"AES256";

    if((alg == L"aes256" || alg == L"aes-256") && mode == L"cfb")
      return L"AES256/CFB";

    if((alg == L"aes256" || alg == L"aes-256") && mode == L"ofb")
      return L"AES256/OFB";

    if((alg == L"aes256" || alg == L"aes-256") && mode == L"ctr")
      return L"AES256/CTR";

    if(alg == L"camellia" && mode == L"")
      return L"Camellia";

    if(alg == L"camellia" && mode == L"cfb")
      return L"Camellia/CFB";

    if(alg == L"camellia" && mode == L"ofb")
      return L"Camellia/OFB";

    if(alg == L"camellia" && mode == L"ctr")
      return L"Camellia/CTR";

    if(alg == L"camellia128" && mode == L"")
      return L"Camellia128";

    if((alg == L"camellia128" || alg == L"camellia-128") && mode == L"cfb")
      return L"Camellia128/CFB";

    if((alg == L"camellia128" || alg == L"camellia-128") && mode == L"ofb")
      return L"Camellia128/OFB";

    if((alg == L"camellia128" || alg == L"camellia-128") && mode == L"ctr")
      return L"Camellia128/CTR";

    if(alg == L"camellia192" && mode == L"")
      return L"Camellia192";

    if((alg == L"camellia192" || alg == L"camellia-192") && mode == L"cfb")
      return L"Camellia192/CFB";

    if((alg == L"camellia192" || alg == L"camellia-192") && mode == L"ofb")
      return L"Camellia192/OFB";

    if((alg == L"camellia192" || alg == L"camellia-192") && mode == L"ctr")
      return L"Camellia192/CTR";

    if(alg == L"camellia256" && mode == L"")
      return L"Camellia256";

    if((alg == L"camellia256" || alg == L"camellia-256") && mode == L"cfb")
      return L"Camellia256/CFB";

    if((alg == L"camellia256" || alg == L"camellia-256") && mode == L"ofb")
      return L"Camellia256/OFB";

    if((alg == L"camellia256" || alg == L"camellia-256") && mode == L"ctr")
      return L"Camellia256/CTR";

    if(alg == L"blowfish" && mode == L"")
      return L"Blowfish";

    if(alg == L"blowfish" && mode == L"cfb")
      return L"Blowfish/CFB";

    if(alg == L"blowfish" && mode == L"ofb")
      return L"Blowfish/OFB";

    if(alg == L"blowfish" && mode == L"ctr")
      return L"Blowfish/CTR";

    if((alg == L"desede" || alg == L"desede112" || alg == L"desede-112") && mode == L"")
      return L"DES_ede";

    if((alg == L"desede" || alg == L"desede112" || alg == L"desede-112") && mode == L"cfb")
      return L"DES_ede/CFB";

    if((alg == L"desede" || alg == L"desede112" || alg == L"desede-112") && mode == L"ofb")
      return L"DES_ede/OFB";

    if((alg == L"desede" || alg == L"desede112" || alg == L"desede-112") && mode == L"ctr")
      return L"DES_ede/CTR";

    ////////////////////////////////// Hashes //////////////////////////////////

    if(alg == L"sha-1" || alg == L"sha1" || alg == L"sha")
      return L"SHA-1";

    if(alg == L"sha-224" || alg == L"sha224")
      return L"SHA-224";

    if(alg == L"sha-256" || alg == L"sha256")
      return L"SHA-256";

    if(alg == L"sha-384" || alg == L"sha384")
      return L"SHA-384";

    if(alg == L"sha-512" || alg == L"sha512")
      return L"SHA-512";

    if(alg == L"whirlpool")
      return L"Whirlpool";

    ////////////////////////////////// HMACs //////////////////////////////////

    if(alg == L"hmacsha-1" || alg == L"hmacsha1" || alg == L"hmacsha")
      return L"HmacSHA1";

    if(alg == L"hmacsha-224" || alg == L"hmacsha224")
      return L"HmacSHA224";

    if(alg == L"hmacsha-256" || alg == L"hmacsha256")
      return L"HmacSHA256";

    if(alg == L"hmacsha-384" || alg == L"hmacsha384")
      return L"HmacSHA384";

    if(alg == L"hmacsha-512" || alg == L"hmacsha512")
      return L"HmacSHA512";

    if(alg == L"hmacwhirlpool")
      return L"HmacWhirlpool";

    return trimmed;
  }
} // esapi

