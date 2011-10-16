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

#include "EsapiCommon.h"
#include "util/SecureArray.h"
#include "errors/EncryptionException.h"
#include "errors/NoSuchAlgorithmException.h"
#include "errors/IllegalArgumentException.h"

#include <string>

namespace esapi
{
  ///////////////////////////////////////////////////////////////////////////////////
  /////////////////////////// Secure Random Implmentation ///////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////

  class SecureRandomBase : private NotCopyable
  {
    // SecureRandom needs access to createInstance() and getSecurityLevel()
    friend class SecureRandom;

  public:
    /**
     * Destroy this random number generator (RNG).
     */
    virtual ~SecureRandomBase() { };

  protected:
    /**
     * Factory method to cough up an implementation.
     * Java offers a SecureRandom(byte[]), and this overload handles it.
     */
    static SecureRandomBase* createInstance(const NarrowString& algorithm, const byte* seed, size_t size);

    /**
     * Constructs a secure random number generator (RNG) implementing the named
     * random number algorithm.
     */
    explicit SecureRandomBase(const NarrowString& algorithm, const byte* seed, size_t size);

    /**
     * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
     */
    virtual SecureByteArray generateSeedImpl(unsigned int numBytes) = 0;

    /**
     * Returns the name of the algorithm implemented by this SecureRandomBase object.
     */
    virtual NarrowString getAlgorithmImpl() const;

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
     * A catastrophic error was encountered. For example, failing to provide a valid seed
     * buffer *is not* catastrophic. An internal Crypto++ error *is* catastrohic.
     */
    bool m_catastrophic;

  private:

    /**
     * The standard algorithm name.
     */
    AlgorithmName m_algorithm;
  };

  ///////////////////////////////////////////////////////////////////////////////////////

  template<unsigned int SECLEVEL, unsigned int SEEDLEN>
    struct DrbgInfo
    {
      enum { SecurityLevel = SECLEVEL, SeedLength = SEEDLEN };
    };

  template <class CIPHER, template <class CPHR> class MODE, class DRBGINFO>
    class BlockCipherImpl : public SecureRandomBase
  {
    // createInstance() needs to call new on the class
    friend SecureRandomBase* SecureRandomBase::createInstance(const NarrowString&, const byte*, size_t);

    // Security levels are 80, 112, 128, ... The enum specifies bytes.
    // Seed length is 440 0r 888 bits, depending on the security level. The enum specifies bytes.
    enum { SecurityLevel = DRBGINFO::SecurityLevel, SeedLength = DRBGINFO::SeedLength, SeedBits = SeedLength*8 };
    // Max reseed <= 2^48, we settle on 4 * 1000. The enum specifies a count.
    // Max request is <= 2^19 bits, which is 2^16 bytes (8 = 2^3). The enum specifies bytes.
    enum { MaxReseed = (1 << 12), MaxRequest = (1 << 16) };

  protected:
    explicit BlockCipherImpl(const NarrowString& algorithm, const byte* seed = nullptr, size_t size = 0);
    virtual ~BlockCipherImpl() { };
    virtual SecureByteArray generateSeedImpl(unsigned int numBytes);
    virtual NarrowString getAlgorithmImpl() const;
    virtual unsigned int getSecurityLevelImpl() const;
    virtual void nextBytesImpl(byte bytes[], size_t size);
    virtual void setSeedImpl(const byte seed[], size_t size);
    virtual void setSeedImpl(int seed);

  private:
    CryptoPP::SecByteBlock m_v;
    CryptoPP::SecByteBlock m_c;
    size_t m_rctr;
  };

  ///////////////////////////////////////////////////////////////////////////////////////

  template <class HASH, class DRBGINFO>
    class HashImpl : public SecureRandomBase
  {
    // createInstance() needs to call new on the class
    friend SecureRandomBase* SecureRandomBase::createInstance(const NarrowString&, const byte*, size_t);

    // Security levels are 80, 112, 128, ... The enum specifies bytes.
    // Seed length is 440 0r 888 bits, depending on the security level. The enum specifies bytes.
    enum { SecurityLevel = DRBGINFO::SecurityLevel, SeedLength = DRBGINFO::SeedLength, SeedBits = SeedLength*8 };
    // Max reseed <= 2^48, we settle on 4 * 1000. The enum specifies a count.
    // Max request is <= 2^19 bits, which is 2^16 bytes (8 = 2^3). The enum specifies bytes.
    enum { MaxReseed = (1 << 12), MaxRequest = (1 << 16) };

  protected:
    explicit HashImpl(const NarrowString& algorithm, const byte* seed = nullptr, size_t size = 0);
    virtual ~HashImpl() { };
    virtual SecureByteArray generateSeedImpl(unsigned int numBytes);
    virtual NarrowString getAlgorithmImpl() const;
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

  ///////////////////////////////////////////////////////////////////////////////////////

  template <class HASH, class DRBGINFO>
    class HmacImpl : public SecureRandomBase
  {
    // createInstance() needs to call new on the class
    friend SecureRandomBase* SecureRandomBase::createInstance(const NarrowString&, const byte*, size_t);

    // Security levels are 80, 112, 128, ... The enum specifies bytes.
    // Seed length is 440 0r 888 bits, depending on the security level. The enum specifies bytes.
    enum { SecurityLevel = DRBGINFO::SecurityLevel, DigestLength = CryptoPP::HMAC<HASH>::DIGESTSIZE,
           SeedLength = DRBGINFO::SeedLength, SeedBits = SeedLength*8 };
    // Max reseed <= 2^48, we settle on 4 * 1000. The enum specifies a count.
    // Max request is <= 2^19 bits, which is 2^16 bytes (8 = 2^3). The enum specifies bytes.
    enum { MaxReseed = (1 << 12), MaxRequest = (1 << 16) };

  protected:
    HmacImpl(const NarrowString& algorithm, const byte* seed = nullptr, size_t size = 0);
    virtual ~HmacImpl() { };
    virtual SecureByteArray generateSeedImpl(unsigned int numBytes);
    virtual NarrowString getAlgorithmImpl() const;
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
} // NAMESPACE
