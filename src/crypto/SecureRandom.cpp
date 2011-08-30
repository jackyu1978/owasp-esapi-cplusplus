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
#include "crypto/Crypto++Common.h"
#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

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
  std::string SecureRandom::DefaultAlgorithm()
  {
    return std::string("SHA-256");
  }

  /**
   * Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
   */
  SecureRandom SecureRandom::getInstance(const std::string& algorithm)
  {
    const std::string alg(algorithm.c_str(), algorithm.length());
    const std::string normal = normalizeAlgortihm(alg);
    ASSERT( !normal.empty() );

    if(normal.empty())
      {
        std::ostringstream oss;
        oss << "Algorithm \'" << algorithm << "\' is not supported.";
        throw EncryptionException(oss.str());
      }

    MEMORY_BARRIER();
    SecureRandomImpl* impl = SecureRandomImpl::createInstance(normal);

    ASSERT(impl != nullptr);
    if(impl == nullptr)
      throw EncryptionException("Failed to create SecureRandom");

    return SecureRandom(impl);
  }

  /**
   * Constructs a secure random number generator (RNG) implementing the named
   * random number algorithm if specified
   */
  SecureRandom::SecureRandom(const std::string& algorithm)
    : m_lock(new Mutex), m_impl(SecureRandomImpl::createInstance(normalizeAlgortihm(algorithm)))
  {
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
    // This is an oddball case. Because we have a seed, we need the
    // default generator with additional entropy. So the SHA classes
    // provide an alternat CTOR for the job.

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
  }

  /**
   * Copy this secure random number generator (RNG).
   */
  SecureRandom::SecureRandom(const SecureRandom& rhs)
    : m_lock(rhs.m_lock), m_impl(rhs.m_impl)
  {
  }

  /**
   * Assign this secure random number generator (RNG).
   */
  SecureRandom& SecureRandom::operator=(const SecureRandom& rhs)
  {
    if(this != &rhs)
    {
      m_lock = rhs.m_lock;
      m_impl = rhs.m_impl;
    }

    return *this;
  }

  /**
   * Retrieves the object level lock
   */
  Mutex& SecureRandom::getObjectLock() const
  {
    ASSERT(m_lock.get());
    return *(m_lock.get());
  }

  /**
   * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
   */
  byte* SecureRandom::generateSeed(unsigned int numBytes)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    throw std::runtime_error("Not implemented");
  }

  /**
   * Returns the name of the algorithm implemented by this SecureRandom object.
   */
  std::string SecureRandom::getAlgorithm() const
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->getAlgorithmImpl();
  }  

  /**
   * Returns the security level associated with the SecureRandom object. Used
   * by KeyGenerator to determine the appropriate key size for init.
   */
  unsigned int SecureRandom::getSecurityLevel() const
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve security level");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->getSecurityLevelImpl();
  }

  /**
   * Generates a user-specified number of random bytes.
   */
  void SecureRandom::nextBytes(byte bytes[], size_t size)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to generate random bytes");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    m_impl->nextBytesImpl(bytes, size);
  }

  /**
   * Reseeds this random object.
   */
  void SecureRandom::setSeed(const byte seed[], size_t size)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to seed the generator");

    // No need to lock - RandomPool provides its own
    RandomPool::GetSharedInstance().Reseed();

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    m_impl->setSeedImpl(seed, size);
  }

  /**
   * Reseeds this random object, using the bytes contained in the given long seed.
   */
  void SecureRandom::setSeed(int seed)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to seed the generator");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    m_impl->setSeedImpl((const byte*)&seed, sizeof(seed));
  }

  /**
   * Normalizes the algorithm name. An empty string on input is interpreted as
   * the default algortihm. If the algorithm is not found (ie, unsupported),
   * return the empty string.
   */
  std::string SecureRandom::normalizeAlgortihm(const std::string& algorithm)
  {
    std::string alg = algorithm, mode;
    std::string::size_type pos;

    // Cut out whitespace
    std::string::iterator it = std::remove_if(alg.begin(), alg.end(), ::isspace);
    if(it != alg.end())
      alg.erase(it, alg.end());

    // Select default algorithm if empty
    if(alg.empty())
      alg = DefaultAlgorithm();

    // Normalize the case
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    // Normalize the slashes (we expect forward slashes, not back slashes)
    while(std::string::npos != (pos = alg.find('\\')))
      alg.replace(pos, 1, "/");

    // Split the string between CIPHER/MODE. Note that there might also be padding, but we ignore it
    if(std::string::npos != (pos = alg.find('/')))
      {
        mode = alg.substr(pos+1);
        alg.erase(pos);
      }

    // Lop off anything remaining in the mode such as padding - we always use Crypto++ default padding
    if(std::string::npos != (pos = mode.find('/')))
      mode.erase(pos);

    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html

    ////////////////////////////////// Block Ciphers //////////////////////////////////

    if(alg == "aes" && mode == "")
      return "AES";

    if(alg == "aes" && mode == "cfb")
      return "AES/CFB";

    if(alg == "aes" && mode == "ofb")
      return "AES/OFB";

    if(alg == "aes" && mode == "ctr")
      return "AES/CTR";

    if((alg == "aes128" || alg == "aes-128") && mode == "")
      return "AES128";

    if((alg == "aes128" || alg == "aes-128") && mode == "cfb")
      return "AES128/CFB";

    if((alg == "aes128" || alg == "aes-128") && mode == "ofb")
      return "AES128/OFB";

    if((alg == "aes128" || alg == "aes-128") && mode == "ctr")
      return "AES128/CTR";

    if((alg == "aes192" || alg == "aes-192") && mode == "")
      return "AES192";

    if((alg == "aes192" || alg == "aes-192") && mode == "cfb")
      return "AES192/CFB";

    if((alg == "aes192" || alg == "aes-192") && mode == "ofb")
      return "AES192/OFB";

    if((alg == "aes192" || alg == "aes-192") && mode == "ctr")
      return "AES192/CTR";

    if((alg == "aes256" || alg == "aes-256") && mode == "")
      return "AES256";

    if((alg == "aes256" || alg == "aes-256") && mode == "cfb")
      return "AES256/CFB";

    if((alg == "aes256" || alg == "aes-256") && mode == "ofb")
      return "AES256/OFB";

    if((alg == "aes256" || alg == "aes-256") && mode == "ctr")
      return "AES256/CTR";

    if(alg == "camellia" && mode == "")
      return "Camellia";

    if(alg == "camellia" && mode == "cfb")
      return "Camellia/CFB";

    if(alg == "camellia" && mode == "ofb")
      return "Camellia/OFB";

    if(alg == "camellia" && mode == "ctr")
      return "Camellia/CTR";

    if(alg == "camellia128" && mode == "")
      return "Camellia128";

    if((alg == "camellia128" || alg == "camellia-128") && mode == "cfb")
      return "Camellia128/CFB";

    if((alg == "camellia128" || alg == "camellia-128") && mode == "ofb")
      return "Camellia128/OFB";

    if((alg == "camellia128" || alg == "camellia-128") && mode == "ctr")
      return "Camellia128/CTR";

    if(alg == "camellia192" && mode == "")
      return "Camellia192";

    if((alg == "camellia192" || alg == "camellia-192") && mode == "cfb")
      return "Camellia192/CFB";

    if((alg == "camellia192" || alg == "camellia-192") && mode == "ofb")
      return "Camellia192/OFB";

    if((alg == "camellia192" || alg == "camellia-192") && mode == "ctr")
      return "Camellia192/CTR";

    if(alg == "camellia256" && mode == "")
      return "Camellia256";

    if((alg == "camellia256" || alg == "camellia-256") && mode == "cfb")
      return "Camellia256/CFB";

    if((alg == "camellia256" || alg == "camellia-256") && mode == "ofb")
      return "Camellia256/OFB";

    if((alg == "camellia256" || alg == "camellia-256") && mode == "ctr")
      return "Camellia256/CTR";

    if(alg == "blowfish" && mode == "")
      return "Blowfish";

    if(alg == "blowfish" && mode == "cfb")
      return "Blowfish/CFB";

    if(alg == "blowfish" && mode == "ofb")
      return "Blowfish/OFB";

    if(alg == "blowfish" && mode == "ctr")
      return "Blowfish/CTR";

    if((alg == "desede" || alg == "desede112" || alg == "desede-112") && mode == "")
      return "DES_ede";

    if((alg == "desede" || alg == "desede112" || alg == "desede-112") && mode == "cfb")
      return "DES_ede/CFB";

    if((alg == "desede" || alg == "desede112" || alg == "desede-112") && mode == "ofb")
      return "DES_ede/OFB";

    if((alg == "desede" || alg == "desede112" || alg == "desede-112") && mode == "ctr")
      return "DES_ede/CTR";

    ////////////////////////////////// Hashes //////////////////////////////////

    if(alg == "sha-1" || alg == "sha1" || alg == "sha")
      return "SHA-1";

    if(alg == "sha-224" || alg == "sha224")
      return "SHA-224";

    if(alg == "sha-256" || alg == "sha256")
      return "SHA-256";

    if(alg == "sha-384" || alg == "sha384")
      return "SHA-384";

    if(alg == "sha-512" || alg == "sha512")
      return "SHA-512";

    if(alg == "whirlpool")
      return "Whirlpool";

    ////////////////////////////////// HMACs //////////////////////////////////

    if(alg == "hmacsha-1" || alg == "hmacsha1" || alg == "hmacsha")
      return "HmacSHA1";

    if(alg == "hmacsha-224" || alg == "hmacsha224")
      return "HmacSHA224";

    if(alg == "hmacsha-256" || alg == "hmacsha256")
      return "HmacSHA256";

    if(alg == "hmacsha-384" || alg == "hmacsha384")
      return "HmacSHA384";

    if(alg == "hmacsha-512" || alg == "hmacsha512")
      return "HmacSHA512";

    if(alg == "hmacwhirlpool")
      return "HmacWhirlpool";

    return "";
  }
} // esapi
