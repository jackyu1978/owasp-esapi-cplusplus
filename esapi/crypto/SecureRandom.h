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

#pragma once

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "util/NotCopyable.h"
#include "crypto/RandomPool.h"
#include "crypto/Crypto++Common.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

#include <string>
#include <vector>
#include <stdexcept>
#include <cassert>

#include <boost/shared_ptr.hpp>

namespace esapi
{
  /**
   * This class implements functionality similar to Java's SecureRandom for consistency
   * http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html
   */

  class SecureRandomImpl;

  ///////////////////////////////////////////////////////////////////////////////////
  ////////////////////////////////// Secure Random //////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////

  class ESAPI_EXPORT SecureRandom
  {
    // KeyGenerator needs access to getSecurityLevel()
    friend class KeyGenerator;

    // While it make sense to make DefaultAlgorithm public static objects, we can't
    // be sure of initializtion order of non-local statics. So they become functions.

  public:
    /**
     * The default secure random number generator (RNG) algorithm. SHA-1 is approved for
     * Random Number Generation. See SP 800-90 Table 2 (p.34) and Table 3 (p.46) and SP800-57.
     */
    static std::string DefaultAlgorithm();

    /**
     * Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
     */
    static SecureRandom getInstance(const std::string& algorithm);

    /**
     * Constructs a secure random number generator (RNG) implementing the named
     * random number algorithm if specified
     */
    explicit SecureRandom(const std::string& algorithm = DefaultAlgorithm());

    /**
     * Constructs a secure random number generator (RNG) implementing the default random number algorithm.
     */
    explicit SecureRandom(const byte* seed, size_t size);

    /**
     * Destroy this random number generator (RNG).
     */
    ~SecureRandom() { };

    /**
     * Copy this secure random number generator (RNG).
     */
    SecureRandom(const SecureRandom& rhs);

    /**
     * Assign this secure random number generator (RNG).
     */
    SecureRandom& operator=(const SecureRandom& rhs);

    /**
     * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
     */
    byte* generateSeed(unsigned int numBytes);

    /**
     * Returns the name of the algorithm implemented by this SecureRandom object.
     */
    std::string getAlgorithm() const;

    /**
     * Generates a user-specified number of random bytes.
     */
    void nextBytes(byte* bytes, size_t size);

    /**
     * Reseeds this random object.
     */
    void setSeed(const byte seed[], size_t size);

    /**
     * Reseeds this random object, using the bytes contained in the given long seed.
     */
    void setSeed(int seed);

  protected:

    /**
     * Normalizes the algorithm name. An empty string on input is interpreted as
     * the default algortihm. If the algorithm is not found (ie, unsupported),
     * return the empty string.
     */
    static std::string normalizeAlgortihm(const std::string& algorithm);

    /**
     * Constructs a secure random number generator (RNG) algorithm name
     * and SecureRandomImpl implementation.
     */
    SecureRandom(SecureRandomImpl* impl);

    /**
     * Returns the security level associated with the SecureRandom object. Used
     * by KeyGenerator to determine the appropriate key size for init.
     */
    unsigned int getSecurityLevel() const;

  protected:

    /**
     * shared_ptr is reference counted. Its how we work magic with assignment and copy
     */
    boost::shared_ptr<SecureRandomImpl> m_impl;
  };

  ///////////////////////////////////////////////////////////////////////////////////
  /////////////////////////// Secure Random Implmentation ///////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////

  class SecureRandomImpl : private NotCopyable
  {
    // SecureRandom needs access to createInstance() and getSecurityLevel()
    friend class SecureRandom;

  protected:
    /**
     * A shared pool for all PRNG objects. Note this is a reference to a RandomPool,
     * and not a copy. Its initalized in the CPP file.
     */
    static RandomPool& g_pool;

  public:
    /**
     * Destroy this random number generator (RNG).
     */
    virtual ~SecureRandomImpl() { };

  protected:
    /**
     * Factory method to cough up an implementation.
     * Java offers a SecureRandom(byte[]), and this overload handles it.
     */
    static SecureRandomImpl* createInstance(const std::string& algorithm, const byte* seed = nullptr, size_t size = 0);

    /**
     * Constructs a secure random number generator (RNG) implementing the named
     * random number algorithm.
     */
    explicit SecureRandomImpl(const std::string& algorithm, const byte* seed = nullptr, size_t size = 0);

    /**
     * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
     */
    virtual byte* generateSeedImpl(unsigned int numBytes) = 0;

    /**
     * Returns the name of the algorithm implemented by this SecureRandomImpl object.
     */
    virtual std::string getAlgorithmImpl() const;

    /**
     * Returns the security level associated with the SecureRandom object. Used
     * by KeyGenerator to determine the appropriate key size for init.
     */
    virtual unsigned int getSecurityLevelImpl() const = 0;

    /**
     * Generates a user-specified number of random bytes.
     */
    virtual void nextBytesImpl(byte bytes[], size_t size) = 0;

    /**
     * Reseeds this random object.
     */
    virtual void setSeedImpl(const byte seed[], size_t size) = 0;

    /**
     * Reseeds this random object, using the bytes contained in the given long seed.
     */
    virtual void setSeedImpl(int seed) = 0;

  protected:

    /**
     * Retrieves the object level lock
     */
    inline Mutex& getObjectLock() const;

    /**
     * Convenience function to move a big integer into a buffer
     */
    inline void IntegerToBuffer(const CryptoPP::Integer& n, byte* buff, size_t bsize);

    /**
     * A catastrophic error was encountered. For example, failing to provide a valid seed
     * buffer *is not* catastrophic. An internal Crypto++ error *is* catastrohic.
     */
    bool m_catastrophic;

  private:

    /**
     * The standard algorithm name.
     */
    std::string m_algorithm;

    /**
     * Object level lock for concurrent access
     */
    mutable boost::shared_ptr<Mutex> m_lock;
  };

  ///////////////////////////////////////////////////////////////////////////////////
  ///////////////////////// Secure Random Impl Derivations //////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////

  template<unsigned int SECLEVEL, unsigned int SEEDLEN>
    struct DrbgInfo
    {
      enum { SecurityLevel = SECLEVEL, SeedLength = SEEDLEN };
    };

  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
    class BlockCipherImpl : public SecureRandomImpl
  {
    // createInstance() needs to call new on the class
    friend SecureRandomImpl* SecureRandomImpl::createInstance(const std::string&, const byte*, size_t);

    // Security levels are 80, 112, 128, ... The enum specifies bytes.
    // Seed length is 440 0r 888 bits, depending on the security level. The enum specifies bytes.
    enum { SecurityLevel = DRBGINFO::SecurityLevel, SeedLength = DRBGINFO::SeedLength, SeedBits = SeedLength*8 };
    // Max reseed <= 2^48, we settle on 4 * 1000. The enum specifies a count.
    // Max request is <= 2^19 bits, which is 2^16 bytes (8 = 2^3). The enum specifies bytes.
    enum { MaxReseed = (1 << 12), MaxRequest = (1 << 16) };

  protected:
    explicit BlockCipherImpl(const std::string& algorithm, const byte* seed = nullptr, size_t size = 0);
    virtual ~BlockCipherImpl() { };
    virtual byte* generateSeedImpl(unsigned int numBytes);
    virtual std::string getAlgorithmImpl() const;
    virtual unsigned int getSecurityLevelImpl() const;
    virtual void nextBytesImpl(byte bytes[], size_t size);
    virtual void setSeedImpl(const byte seed[], size_t size);
    virtual void setSeedImpl(int seed);
  };

  template <class HASH, class DRBGINFO>
    class HashImpl : public SecureRandomImpl
  {
    // createInstance() needs to call new on the class
    friend SecureRandomImpl* SecureRandomImpl::createInstance(const std::string&, const byte*, size_t);

    // Security levels are 80, 112, 128, ... The enum specifies bytes.
    // Seed length is 440 0r 888 bits, depending on the security level. The enum specifies bytes.
    enum { SecurityLevel = DRBGINFO::SecurityLevel, SeedLength = DRBGINFO::SeedLength, SeedBits = SeedLength*8 };
    // Max reseed <= 2^48, we settle on 4 * 1000. The enum specifies a count.
    // Max request is <= 2^19 bits, which is 2^16 bytes (8 = 2^3). The enum specifies bytes.
    enum { MaxReseed = (1 << 12), MaxRequest = (1 << 16) };

  protected:
    explicit HashImpl(const std::string& algorithm, const byte* seed = nullptr, size_t size = 0);
    virtual ~HashImpl() { };
    virtual byte* generateSeedImpl(unsigned int numBytes);
    virtual std::string getAlgorithmImpl() const;
    virtual unsigned int getSecurityLevelImpl() const;
    virtual void nextBytesImpl(byte bytes[], size_t size);
    virtual void setSeedImpl(const byte seed[], size_t size);
    virtual void setSeedImpl(int seed);

  private:
    void HashInstantiate(const byte* seed, size_t ssize);
    void HashInitBufferWithData(const byte purpose, const byte* data, size_t dsize, byte* buffer, size_t bsize);
    void HashDerivationFunction(const byte* data, size_t dsize, byte* hash, size_t hsize);
    void HashGenerate(byte* hash, size_t hsize);
    void HashGenerateHelper(byte* hash, size_t hsize);
    void HashReseed(const byte* seed, size_t ssize);

  private:
    HASH m_hash;
    CryptoPP::SecByteBlock m_v;
    CryptoPP::SecByteBlock m_c;
    size_t m_rctr;
  };

  template <class HASH, class DRBGINFO>
    class HmacImpl : public SecureRandomImpl
  {
    // createInstance() needs to call new on the class
    friend SecureRandomImpl* SecureRandomImpl::createInstance(const std::string&, const byte*, size_t);

    // Security levels are 80, 112, 128, ... The enum specifies bytes.
    // Seed length is 440 0r 888 bits, depending on the security level. The enum specifies bytes.
    enum { SecurityLevel = DRBGINFO::SecurityLevel, DigestLength = CryptoPP::HMAC<HASH>::DIGESTSIZE,
           SeedLength = DRBGINFO::SeedLength, SeedBits = SeedLength*8 };
    // Max reseed <= 2^48, we settle on 4 * 1000. The enum specifies a count.
    // Max request is <= 2^19 bits, which is 2^16 bytes (8 = 2^3). The enum specifies bytes.
    enum { MaxReseed = (1 << 12), MaxRequest = (1 << 16) };

  protected:
    HmacImpl(const std::string& algorithm, const byte* seed = nullptr, size_t size = 0);
    virtual ~HmacImpl() { };
    virtual byte* generateSeedImpl(unsigned int numBytes);
    virtual std::string getAlgorithmImpl() const;
    virtual unsigned int getSecurityLevelImpl() const;
    virtual void nextBytesImpl(byte bytes[], size_t size);
    virtual void setSeedImpl(const byte seed[], size_t size);
    virtual void setSeedImpl(int seed);

  private:
    void HmacInstantiate(const byte* seed, size_t ssize);
    void HmacUpdate(const byte* data, size_t dsize);
    void HmacGenerate(byte* hash, size_t hsize);
    void HmacReseed(const byte* seed, size_t ssize);

  private:
    CryptoPP::HMAC<HASH> m_hmac;
    CryptoPP::SecByteBlock m_v;
    CryptoPP::SecByteBlock m_k;
    size_t m_rctr;
  };

}; // NAMESPACE esapi
