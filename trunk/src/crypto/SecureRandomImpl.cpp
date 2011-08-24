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
#include "crypto/RandomPool.h"
#include "crypto/SecureRandom.h"
#include "crypto/Crypto++Common.h"
#include "safeint/SafeInt3.hpp"
#include "util/ArrayZeroizer.h"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

/**
 * This class implements functionality similar to Java's SecureRandom for consistency
 * http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html.
 *
 * SP800-90, 'Recommendation for Random Number Generation Using Deterministic
 * Random Bit Generators'. SP800-90 algorithms are used for Hash, Hmac, and
 * Block Ciphers. For Block ciphers, SP800-90 specifies CTR mode. The counter
 * is a special case of an IV with [possibly] a nonce and monotomically
 * increasing values. For non-CTR modes (ie, AES/CFB), we use a random IV
 * drawn from the Random Pool.
 *
 * Seed material is {entropy || nonce || personalization}. Entropy is *not* the
 * user provided seed bytes per Section 8.7.2. Instead, enropy is a string of
 * bits obtained from a "Source of Entropy" (SEI) per Section 10. A "Source of
 * Entropy" produces unpredictable data per Appendix C. Appendix C recommends
 * for example, a Geiger counter or noisy diode. Obviously, we don't expect
 * to have a Geiger counter on a COMM or USB port.
 *
 * SecureRandom defers to ESAPI's RandomPool for unpredictable data. RandomPool
 * is the "Source of Entropy" abstraction, and is mildly intelligent about drawing
 * bits from its supported sources. For example, on Windows the pool will attempt
 * to pull bytes from an Intel i8XX chipset (a hardware based RNG). On Linux,
 * it will attempt to acquire bits via /dev/random *without* blocking. If bits are
 * not available from preferred sources, the pool will fall back to the default CSP
 * on Windows, or /dev/urandom from Linux. IF you have an EntropyKey
 * (http://www.entropykey.co.uk/) jacked in, you will most likely always seed
 * from /dev/random. During testing, I could never drain /dev/random with an
 * EntropyKey present.
 *
 * Getting back to {entropy || nonce || personalization}: a user provided seed is
 * considered "Additional Input" per Section 8.7.2, so don't confuse it with 'entropy'.
 * The nonce is an additional unpredictable value (more on nonce and its
 * relationship with entropy below). The personalization string is more unique
 * data such as device UUID, host name, user name, or public key (per Section 8.6.7).
 * The personalization string is known by other names in other documents and standards,
 * such as a 'purpose', 'label', and 'context info'. Per 8.6.7, its OK to forego a
 * Personalization String.
 *
 * When instantiating a generator, we *must* have entropy. If we don't have entropy,
 * its a catastrohpic failure. Because of the Random Pool, we can expect to have
 * entropy. Each generator performs to a specific Security Level. The amount of
 * entropy we need is related to the cipher/algorithm, the security level and
 * specified as SeedLength. The nonce should have at least 1/2 SeedLength bits.
 * If the nonce is provided by the same source as entropy (which it is), we need
 * 3/2*SeedLength per Section 8.6.7.
 *
 * Instantiating a generator to a Security Level means our RandomPool must match
 * security levels. To keep a single pool for all generators, the Random Pool
 * uses AES-256/OFB. AES-256/OFB matches the security level of the strongest
 * SecureRandoms we provide (ie, SHA-512, HmacSHA-512, AES-256/CTR). Weaker
 * SecureRandoms (ie, SHA-1) are slightly penalized due to the stronger RandomPool
 * algorithm.
 *
 * Enough with the background info. When we instantiate, here's what we do:
 *   seed_material = Entropy (SeedLength bits from Random Pool) ||
 *                   Nonce (1/2 SeedLength bits from Random Pool) ||
 *                   Personalization String (the user provided seed)
 *
 * Some generators need to preporcess seed_material (cf, Hash), others do
 * not. Regardless, Instantiate() occurs with seed_material dominated by
 * the Random Pool.
 *
 * Reseeding is similar in operation. We fetch new bytes from the Random Pool
 * and mix in user supplied data (ie, their 'seed') to arrive at seed_material:
 *   seed_material = Entropy (SeedLength bits from Random Pool) ||
 *                   Additional Data (the user provided seed)
 *
 * The reseed algorithms include [some] previous state during the operation.
 * There is a limit on how much 'seed' data the user can provide (~2^16 per
 * the Special Publication). If the threshold is exceeded, the PRNG will throw.
 * Under most circumstances, Reseed() will be dominated by previous stated and
 * the Random Pool.
 *
 * Finally, a generator has a finite lifetime. At end of life, the PRNG must
 * be reseeded. The standard does not discuss Auto Seeding, so it is not performed.
 * Instead an exception is thrown after ~2^12 invocations (not bytes). A comment
 * was filed with NIST asking for guidance on Auto Seeding.
 */
namespace esapi
{
  /**
   * Analysis: since this system uses AES-256/OFB mixer for OS provided data, it is
   * no less secure than the raw entropy bits retrieved from the operating system.
   * That is, generating a stream using AES-256/OFB (keyed with /dev/[u]random) is
   * *not* less secure than using /dev/[u]random or CryptGenRandom directly.
   */

  /**
   * A single random pool for use among all generators.
   */
  RandomPool& SecureRandomImpl::g_pool = RandomPool::GetSharedInstance();

  /**
   * Factory method to cough up an implementation.
   * Used by getInstance and most stack based SecureRandoms
   */
  SecureRandomImpl* SecureRandomImpl::createInstance(const std::string& algorithm, const byte* seed, size_t size)
  {

    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html

    ////////////////////////////////// Hashes //////////////////////////////////

    if(algorithm == "SHA-1")
      return new HashImpl<CryptoPP::SHA1, DrbgInfo<10/*80*/, 55/*440*/> >(algorithm, seed, size);

    if(algorithm == "SHA-224")
      return new HashImpl<CryptoPP::SHA224, DrbgInfo<14/*112*/, 55/*440*/> >(algorithm, seed, size);

    if(algorithm == "SHA-256")
      return new HashImpl<CryptoPP::SHA256, DrbgInfo<16/*128*/, 55/*440*/> >(algorithm, seed, size);

    if(algorithm == "SHA-384")
      return new HashImpl<CryptoPP::SHA384, DrbgInfo<24/*192*/, 111/*888*/> >(algorithm, seed, size);

    if(algorithm == "SHA-512")
      return new HashImpl<CryptoPP::SHA512, DrbgInfo<32/*256*/, 111/*888*/> >(algorithm, seed, size);

    if(algorithm == "Whirlpool")
      return new HashImpl<CryptoPP::Whirlpool, DrbgInfo<32/*256*/, 111/*888*/> >(algorithm, seed, size);

    ////////////////////////////////// Block Ciphers //////////////////////////////////

    if(algorithm == "AES" || algorithm == "AES128")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CTR_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "AES/CFB" || algorithm == "AES128/CFB")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CFB_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "AES/OFB" || algorithm == "AES128/OFB")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::OFB_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "AES/CTR" || algorithm == "AES128/CTR")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CTR_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "AES192")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CTR_Mode, DrbgInfo<24/*192*/, 40/*320*/> >(algorithm, seed, size);

    if(algorithm == "AES192/CFB")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CFB_Mode, DrbgInfo<24/*192*/, 40/*320*/> >(algorithm, seed, size);

    if(algorithm == "AES192/OFB")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::OFB_Mode, DrbgInfo<24/*192*/, 40/*320*/> >(algorithm, seed, size);

    if(algorithm == "AES192/CTR")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CTR_Mode, DrbgInfo<24/*192*/, 40/*320*/> >(algorithm, seed, size);

    if(algorithm == "AES256")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CTR_Mode, DrbgInfo<32/*256*/, 48/*384*/> >(algorithm, seed, size);

    if(algorithm == "AES256/CFB")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CFB_Mode, DrbgInfo<32/*256*/, 48/*384*/> >(algorithm, seed, size);

    if(algorithm == "AES256/OFB")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::OFB_Mode, DrbgInfo<32/*256*/, 48/*384*/> >(algorithm, seed, size);

    if(algorithm == "AES256/CTR")
      return new BlockCipherImpl<CryptoPP::AES, CryptoPP::CTR_Mode, DrbgInfo<32/*256*/, 48/*384*/> >(algorithm, seed, size);

    if(algorithm == "Camellia" || algorithm == "Camellia128")
      return new BlockCipherImpl<CryptoPP::Camellia, CryptoPP::CTR_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Camellia/CFB" || algorithm == "Camellia128/CFB")
      return new BlockCipherImpl<CryptoPP::Camellia, CryptoPP::CFB_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Camellia/OFB" || algorithm == "Camellia128/OFB")
      return new BlockCipherImpl<CryptoPP::Camellia, CryptoPP::OFB_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Camellia/CTR" || algorithm == "Camellia128/CTR")
      return new BlockCipherImpl<CryptoPP::Camellia, CryptoPP::CTR_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Blowfish" || algorithm == "Blowfish128")
      return new BlockCipherImpl<CryptoPP::Blowfish, CryptoPP::CTR_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Blowfish/CFB" || algorithm == "Blowfish128/CFB")
      return new BlockCipherImpl<CryptoPP::Blowfish, CryptoPP::CFB_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Blowfish/OFB" || algorithm == "Blowfish128/OFB")
      return new BlockCipherImpl<CryptoPP::Blowfish, CryptoPP::OFB_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "Blowfish/CTR" || algorithm == "Blowfish128/CTR")
      return new BlockCipherImpl<CryptoPP::Blowfish, CryptoPP::CTR_Mode, DrbgInfo<16/*128*/, 32/*256*/> >(algorithm, seed, size);

    if(algorithm == "DES_ede" || algorithm == "DES_ede112")
      return new BlockCipherImpl<CryptoPP::DES_EDE3, CryptoPP::CTR_Mode, DrbgInfo<14/*112*/, 29/*232*/> >(algorithm, seed, size);

    if(algorithm == "DES_ede/CFB" || algorithm == "DES_ede112/CFB")
      return new BlockCipherImpl<CryptoPP::DES_EDE3, CryptoPP::CFB_Mode, DrbgInfo<14/*112*/, 29/*232*/> >(algorithm, seed, size);

    if(algorithm == "DES_ede/OFB" || algorithm == "DES_ede112/OFB")
      return new BlockCipherImpl<CryptoPP::DES_EDE3, CryptoPP::OFB_Mode, DrbgInfo<14/*112*/, 29/*232*/> >(algorithm, seed, size);

    if(algorithm == "DES_ede/CTR" || algorithm == "DES_ede112/CTR")
      return new BlockCipherImpl<CryptoPP::DES_EDE3, CryptoPP::CTR_Mode, DrbgInfo<14/*112*/, 29/*232*/> >(algorithm, seed, size);

    ////////////////////////////////// Hmacs //////////////////////////////////

    if(algorithm == "HmacSHA1")
      return new HmacImpl<CryptoPP::SHA1, DrbgInfo<10/*80*/, 55/*440*/> >(algorithm, seed, size);

    if(algorithm == "HmacSHA224")
      return new HmacImpl<CryptoPP::SHA224, DrbgInfo<14/*112*/, 55/*440*/> >(algorithm, seed, size);

    if(algorithm == "HmacSHA256")
      return new HmacImpl<CryptoPP::SHA256, DrbgInfo<16/*128*/, 55/*440*/> >(algorithm, seed, size);

    if(algorithm == "HmacSHA384")
      return new HmacImpl<CryptoPP::SHA384, DrbgInfo<24/*192*/, 111/*888*/> >(algorithm, seed, size);

    if(algorithm == "HmacSHA512")
      return new HmacImpl<CryptoPP::SHA512, DrbgInfo<32/*256*/, 111/*888*/> >(algorithm, seed, size);

    if(algorithm == "HmacWhirlpool")
      return new HmacImpl<CryptoPP::Whirlpool, DrbgInfo<32/*256*/, 111/*888*/> >(algorithm, seed, size);

    ///////////////////////////////// Catch All /////////////////////////////////

    std::ostringstream oss;
    oss << "Algorithm \'" << algorithm << "\' is not supported.";
    throw EncryptionException(oss.str());
  }

  /**
   * Constructs a secure random number generator (RNG) implementing the named
   * random number algorithm.
   */
  SecureRandomImpl::SecureRandomImpl(const std::string& algorithm, const byte*, size_t)
    : m_catastrophic(false), m_algorithm(algorithm), m_lock(new Mutex)
  {
  }

  /**
   * Returns the name of the algorithm implemented by this SecureRandomImpl object.
   */
  std::string SecureRandomImpl::getAlgorithmImpl() const
  {
    ASSERT( !m_algorithm.empty() );
    return m_algorithm;
  }

  /**
   * Retrieves the object level lock
   */
  Mutex& SecureRandomImpl::getObjectLock() const
  {
    ASSERT(m_lock.get());
    return *(m_lock.get());
  }

  /**
   * Convenience function to move a big integer into a buffer
   */
  void SecureRandomImpl::IntegerToBuffer(const CryptoPP::Integer& n, byte* buff, size_t bsize)
  {
    ASSERT(buff && bsize);
    if(!buff || !bsize) return;

    // In case we need to pad with leading 0s
    const size_t len = n.ByteCount();
    const size_t off = bsize - len;

    ASSERT(bsize >= len);
    if(!(bsize >= len)) return;

    for(size_t i = 0; i < off; i++)
      buff[i] = 0;

    n.Encode(buff+off, len);
  }

  ///////////////////////////////////////////////////////////////
  //////////////////////////// Hashes ///////////////////////////
  ///////////////////////////////////////////////////////////////

  /**
   * Create a SecureRandom implementation based on a hash
   */
  template <class HASH, class DRBGINFO>
  HashImpl<HASH, DRBGINFO>::HashImpl(const std::string& algorithm, const byte* seed, size_t ssize)
    : SecureRandomImpl(algorithm), m_v(SeedLength), m_c(SeedLength), m_rctr(1)
  {
    // seed and size are thinly veiled as "Personalization", and it is optional.
    // If size is non-zero, seed must be valid.
    ASSERT( (!seed && !ssize) || (seed && ssize) );
    if(!seed && ssize)
      throw InvalidArgumentException("The seed buffer or size is not valid");

    try
      {
        // To instantiate, we use {entropy || nonce || personalization}.
        // Since we are drawing entropy and nonce from the same source, we
        // need 3/2*SeedLength rather than just SeedLength (see Section 8.6.7).
        // Personalization is optional. If using the default constructor,
        // it is not present. If using SecureRandom::getInstance(SEED), the
        // seed will be present and used as the personalization string.
        const size_t msize /*seed material size*/ = 3 * SeedLength / 2;
        CryptoPP::SecByteBlock material(msize + ssize);

        g_pool.GenerateBlock(material.data(), msize);

        // Copy in the user provided "personalization"
        if(seed && ssize)
          ::memcpy(material.data()+msize, seed, ssize);

        // All forward facing gear which manipulates internal state acquires the object lock
        // We might not even need locking here - the object has yet to be constructed, so
        // the thread has not returned and the object cannot be copied. We'll do it for
        // good measure to make an audit easier on the eyes.
        MutexAutoLock lock(getObjectLock());

        HashInstantiate(material.data(), material.size());
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Returns the security level associated with the SecureRandom object. Used
   * by KeyGenerator to determine the appropriate key size for init.
   */
  template <class HASH, class DRBGINFO>
  unsigned int HashImpl<HASH, DRBGINFO>::getSecurityLevelImpl() const
  {
    return SecurityLevel;
  }

  /**
   * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
   */
  template <class HASH, class DRBGINFO>
  byte* HashImpl<HASH, DRBGINFO>::generateSeedImpl(unsigned int numBytes)
  {
    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexAutoLock lock(getObjectLock());

    throw std::runtime_error("Not implemented");
  }

  /**
   * Returns the name of the algorithm implemented by this SecureRandom object.
   */
  template <class HASH, class DRBGINFO>
  std::string HashImpl<HASH, DRBGINFO>::getAlgorithmImpl() const
  {
    // Don't throw the catastrophic error here. TThe user might need the name of the generator.

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexAutoLock lock(getObjectLock());

    return SecureRandomImpl::getAlgorithmImpl();
  }

  /**
   * Generates a user-specified number of random bytes.
   */
  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::nextBytesImpl(byte bytes[], size_t size)
  {
    // Assert here. Parameters are validated in HashGenerate()
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    ASSERT(bytes && size);
    ASSERT(m_rctr <= MaxReseed);
    ASSERT(size <= MaxRequest);

    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    try
      {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexAutoLock lock(getObjectLock());

        // Set up a temporary so we don't leak bits on an exception
        CryptoPP::SecByteBlock temp(size);
        HashGenerate(temp.data(), temp.size());

        ::memcpy(bytes, temp.data(), size);
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Reseeds this random object.
   */
  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::setSeedImpl(const byte seed[], size_t size)
  {
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    ASSERT(seed && size);
    if(!seed || !size)
      throw InvalidArgumentException("Unable to reseed the hash drbg. The seed buffer or size is not valid");

    try
      {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexAutoLock lock(getObjectLock());

        HashReseed(seed, size);
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Reseeds this random object, using the bytes contained in the given long seed.
   */
  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::setSeedImpl(int seed)
  {
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    try
      {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexAutoLock lock(getObjectLock());

        setSeedImpl((const byte*)&seed, sizeof(seed));
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * The hash instantiate described in 10.1.1.2.
   */
  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::HashInstantiate(const byte* seed, size_t ssize)
  {
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    ASSERT(seed && ssize);
    if(!seed || !ssize)
      throw InvalidArgumentException("Unable to instatiate hash drbg. The seed buffer or size is not valid");

    try
      {
        HashDerivationFunction(seed, ssize, m_v.data(), m_v.size());

        byte c[SeedLength+1];
        ByteArrayZeroizer z1 (c, sizeof(c));

        HashInitBufferWithData(0x00, m_v.data(), m_v.size(), c, sizeof(c));
        HashDerivationFunction(c, sizeof(c), m_c.data(), m_c.size());
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::HashGenerate(byte* hash, size_t hsize)
  {
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    ASSERT(hash && hsize);
    if( !hash || !hsize )
      throw InvalidArgumentException("Unable to generate bytes from hash drbg. The hash buffer or size is not valid");

    ASSERT(m_rctr <= MaxReseed);
    if( !(m_rctr <= MaxReseed) )
      throw InvalidArgumentException("Unable to generate bytes from hash drbg. A reseed is required.");

    ASSERT(hsize <= MaxRequest);
    if( !(hsize <= MaxRequest) )
      throw InvalidArgumentException("Unable to generate bytes from hash drbg. The requested size exceeds the maximum this DRBG can produce.");

    try
      {
        static const CryptoPP::Integer seedPower2 = CryptoPP::Integer::Power2(SeedBits);
        m_hash.Restart();

        /////////////////////////////////////////////////////////
        // Preprocess V, Steps 1 and 2
        /////////////////////////////////////////////////////////
        byte w[HASH::DIGESTSIZE];
        ByteArrayZeroizer z1(w, sizeof(w));

        static const int two = 0x02;
        m_hash.Update((const byte*)&two, sizeof(two));
        m_hash.Update(m_v.data(), m_v.size());
        m_hash.TruncatedFinal(w, sizeof(w));

        // Can we do this faster with a cascading add rather than using an Integer?
        CryptoPP::Integer v(m_v.data(), m_v.size());
        v += CryptoPP::Integer(w, sizeof(w));
        v %= seedPower2;

        ASSERT(v.ByteCount() <= SeedLength);
        IntegerToBuffer(v, m_v.data(), m_v.size());

        /////////////////////////////////////////////////////////
        // Hashgen, Step 3
        /////////////////////////////////////////////////////////

        HashGenerateHelper(hash, hsize);

        /////////////////////////////////////////////////////////
        // Postprocess V, Steps 4, 5, and 6
        /////////////////////////////////////////////////////////

        static const byte three = 0x03;
        byte h[HASH::DIGESTSIZE];
        ByteArrayZeroizer z2(h, sizeof(h));

        m_hash.Update(&three, sizeof(three));
        m_hash.Update(m_v.data(), m_v.size());
        m_hash.TruncatedFinal(h, sizeof(h));

        // Can we do this faster with a cascading add rather than using an Integer?
        v = CryptoPP::Integer(m_v.data(), m_v.size());
        v += CryptoPP::Integer(h, sizeof(h));
        v += CryptoPP::Integer(m_c.data(), m_c.size());
        v += m_rctr;
        v %= seedPower2;

        ASSERT(v.ByteCount() <= SeedLength);
        IntegerToBuffer(v, m_v.data(), m_v.size());

        /////////////////////////////////////////////////////////
        // Copy out the generated data to the hash
        /////////////////////////////////////////////////////////
        m_rctr++;
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::HashInitBufferWithData(const byte purpose, const byte* data, size_t dsize, byte* buffer, size_t bsize)
  {
    ASSERT(dsize);
    ASSERT(bsize);

    // Need room for purpose
    ASSERT(bsize >= dsize+1);
    if(!(bsize >= dsize+1)) return;

    buffer[0] = purpose;
    ::memcpy(buffer+1, data, dsize);
  }

  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::HashGenerateHelper(byte* hash, size_t hsize)
  {
    ASSERT(SeedLength == m_v.size());

    ASSERT(hash && hsize);
    if( !hash || !hsize )
      throw InvalidArgumentException("Unable to reseed the hash drbg. The seed buffer or size is not valid");

    try
      {
        static const CryptoPP::Integer seedPower2 = CryptoPP::Integer::Power2(SeedBits);
        m_hash.Restart();

        byte data[SeedLength];
        ByteArrayZeroizer z1(data, sizeof(data));

        ::memcpy(data, m_v.data(), m_v.size());
        size_t idx = 0, rem /*remaining*/ = hsize;

        // Write the string W directly into the provided buffer
        // (10.1.1.4 forms W = w_1 || w_2 || ... || w_i)
        while(rem)
          {
            const size_t req = std::min(rem, (size_t)HASH::DIGESTSIZE);
            m_hash.Update(data, sizeof(data));
            m_hash.TruncatedFinal(hash+idx, req);

            // Can we do this faster with a cascading add rather than using an Integer?
            CryptoPP::Integer d(data, sizeof(data));
            d += 1;
            d %= seedPower2;

            ASSERT(d.ByteCount() <= SeedLength);
            IntegerToBuffer(d, data, sizeof(data));

            idx += req;
            rem -= req;
          }
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * The hash derivation function (Hash_df) described in SP 800-90, 10.4.1.
   * {bytes,length} is the seed_material described in 10.1.1.2.
   */
  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::HashDerivationFunction(const byte* data, size_t dsize, byte* hash, size_t hsize)
  {
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    ASSERT(data && dsize);
    if(!data || !dsize)
      throw InvalidArgumentException("Unable to derive hash. The data buffer or size is not valid");

    ASSERT(hash && hsize);
    if(!hash || !hsize)
      throw InvalidArgumentException("Unable to derive hash. The hash buffer or size is not valid");

    static const unsigned int seedBits = SeedBits;
    byte counter = 1;

    try
      {
        size_t idx = 0, rem = hsize;
        while(rem)
          {
            m_hash.Update(&counter, 1);
            m_hash.Update((const byte*)&seedBits, sizeof(seedBits));
            m_hash.Update(data, dsize);

            // Though we call TruncatedFinal, full digest sizes are
            // retireved, except for possibly the last block. Note
            // that TruncatedFinal will reset the hash object.
            const size_t req = std::min(rem,(size_t)HASH::DIGESTSIZE);
            m_hash.TruncatedFinal(hash+idx, req);

            counter++;
            idx += req;
            rem -= req;
          }
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  template <class HASH, class DRBGINFO>
  void HashImpl<HASH, DRBGINFO>::HashReseed(const byte* seed, size_t ssize)
  {
    ASSERT(SeedLength == m_v.size());
    ASSERT(SeedLength == m_c.size());

    ASSERT(seed && ssize);
    if(!seed || !ssize)
      throw InvalidArgumentException("Unable to reseed hash drbg. The seed buffer or size is not valid");

    try
      {
        const size_t msize /*seed material size*/ = 1 + m_v.size() + SeedLength + ssize;
        size_t idx = 0;

        CryptoPP::SecByteBlock material(msize);
        material.data()[idx] = 0x01; idx++;

        ::memcpy(material.data()+idx, m_v.data(), m_v.size());
        idx += m_v.size();

        g_pool.GenerateBlock(material.data()+idx, SeedLength);
        idx += SeedLength;

        if(seed)
          ::memcpy(material.data()+idx, seed, ssize);

        HashDerivationFunction(material.data(), material.size(), m_v.data(), m_v.size());

        byte c[SeedLength+1];
        ByteArrayZeroizer z1(c, sizeof(c));

        HashInitBufferWithData(0x00, m_v.data(), m_v.size(), c, sizeof(c));
        HashDerivationFunction(c, sizeof(c), m_c.data(), m_c.size());

        m_rctr = 1;
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  ///////////////////////////////////////////////////////////////
  ///////////////////////////// Hmacs ///////////////////////////
  ///////////////////////////////////////////////////////////////

  /**
   * Create a SecureRandom implementation based on a block cipher
   */
  template <class HASH, class DRBGINFO>
  HmacImpl<HASH, DRBGINFO>::HmacImpl(const std::string& algorithm, const byte* seed, size_t ssize)
    : SecureRandomImpl(algorithm), m_v(DigestLength), m_k(DigestLength), m_rctr(1)
  {
    // seed and size are optional. If size is non-zero, seed must be valid
    ASSERT( (!seed && !ssize) || (seed && ssize) );
    if(!seed && ssize)
      throw InvalidArgumentException("The seed buffer or size is not valid");

    try
      {
        // To instantiate, we use {entropy || nonce || personalization}.
        // Since we are drawing entropy and nonce from the same source, we
        // need 3/2*SeedLength rather than just SeedLength (see Section 8.6.7).
        // Personalization is optional. If using the default constructor,
        // it is not present. If using SecureRandom::getInstance(SEED), the
        // seed will be present and used as the personalization string.
        const size_t msize /*seed material size*/ = 3 * SeedLength / 2;
        CryptoPP::SecByteBlock material(msize + ssize);

        g_pool.GenerateBlock(material.data(), msize);

        // Copy in the user provided "personalization"
        if(seed && ssize)
          ::memcpy(material.data()+msize, seed, ssize);

        // All forward facing gear which manipulates internal state acquires the object lock
        // We might not even need locking here - the object has yet to be constructed, so
        // the thread has not returned and the object cannot be copied. We'll do it for
        // good measure to make an audit easier on the eyes.
        MutexAutoLock lock(getObjectLock());

        HmacInstantiate(material.data(), material.size());
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Returns the security level associated with the SecureRandom object. Used
   * by KeyGenerator to determine the appropriate key size for init.
   */
  template <class HASH, class DRBGINFO>
  unsigned int HmacImpl<HASH,DRBGINFO>::getSecurityLevelImpl() const
  {
    return SecurityLevel;
  }

  /**
   * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
   */
  template <class HASH, class DRBGINFO>
  byte* HmacImpl<HASH,DRBGINFO>::generateSeedImpl(unsigned int numBytes)
  {
    throw std::runtime_error("Not implemented");
  }

  /**
   * Returns the name of the algorithm implemented by this SecureRandom object.
   */
  template <class HASH, class DRBGINFO>
  std::string HmacImpl<HASH,DRBGINFO>::getAlgorithmImpl() const
  {
    return SecureRandomImpl::getAlgorithmImpl();
  }

  /**
   * Generates a user-specified number of random bytes.
   */
  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::nextBytesImpl(byte bytes[], size_t size)
  {
    // Assert here. Parameters are validated in HmacGenerate()
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    ASSERT(bytes && size);
    ASSERT(m_rctr <= MaxReseed);
    ASSERT(size <= MaxRequest);

    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    try
      {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexAutoLock lock(getObjectLock());

        // Set up a temporary so we don't leak bits on an exception
        CryptoPP::SecByteBlock temp(size);
        HmacGenerate(temp.data(), temp.size());

        ::memcpy(bytes, temp.data(), size);
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Reseeds this random object.
   */
  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::setSeedImpl(const byte seed[], size_t size)
  {
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    ASSERT(seed && size);
    if(!seed || !size)
      throw InvalidArgumentException("Unable to reseed the hmac drbg. The seed buffer or size is not valid");

    try
      {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexAutoLock lock(getObjectLock());

        HmacReseed(seed, size);
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Reseeds this random object, using the bytes contained in the given long seed.
   */
  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::setSeedImpl(int seed)
  {
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    try
      {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexAutoLock lock(getObjectLock());

        setSeedImpl((const byte*)&seed, sizeof(seed));
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      } }

  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::HmacInstantiate(const byte* seed, size_t ssize)
  {
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    ASSERT(seed && ssize);
    if(!seed || !ssize)
      throw InvalidArgumentException("Unable to instatiate hmac drbg. The seed buffer or size is not valid");

    try
      {
        ::memset(m_k.data(), 0x00, m_k.size());
        ::memset(m_v.data(), 0x01, m_v.size());

        m_hmac.SetKey(m_k.data(), m_k.size());

        HmacUpdate(seed, ssize);
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::HmacUpdate(const byte* data, size_t dsize)
  {
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    // data and size are optional. If size is non-zero, seed must be valid
    ASSERT( (!data && !dsize) || (data && dsize) );
    if(!data && dsize)
      throw InvalidArgumentException("The data buffer or size is not valid");

    try
      {
        static const byte zero = 0x00;
        static const byte one = 0x01;

        /////////////////////////////////////////////////////////
        // Re-key, Step 1
        /////////////////////////////////////////////////////////
        m_hmac.Update(m_v.data(), m_v.size());
        m_hmac.Update(&zero, sizeof(zero));
        m_hmac.Update(data, dsize);

        m_hmac.TruncatedFinal(m_k.data(), m_k.size());
        m_hmac.SetKey(m_k.data(), m_k.size());

        /////////////////////////////////////////////////////////
        // Update V, Step 2
        /////////////////////////////////////////////////////////
        m_hmac.Update(m_v.data(), m_v.size());
        m_hmac.TruncatedFinal(m_v.data(), m_v.size());

        /////////////////////////////////////////////////////////
        // Early out, Step 3
        /////////////////////////////////////////////////////////
        if(!data)
          return;

        /////////////////////////////////////////////////////////
        // Re-key, Step 4
        /////////////////////////////////////////////////////////
        m_hmac.Update(m_v.data(), m_v.size());
        m_hmac.Update(&one, sizeof(one));
        m_hmac.Update(data, dsize);

        m_hmac.TruncatedFinal(m_k.data(), m_k.size());
        m_hmac.SetKey(m_k.data(), m_k.size());

        /////////////////////////////////////////////////////////
        // Update V, Step 5
        /////////////////////////////////////////////////////////
        m_hmac.Update(m_v.data(), m_v.size());
        m_hmac.TruncatedFinal(m_v.data(), m_v.size());
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::HmacGenerate(byte* hash, size_t hsize)
  {
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    ASSERT(hash && hsize);
    if( !hash || !hsize )
      throw InvalidArgumentException("Unable to generate bytes from hmac drbg. The hash buffer or size is not valid");

    /////////////////////////////////////////////////////////
    // Sanity check, Step 1
    /////////////////////////////////////////////////////////
    ASSERT(m_rctr <= MaxReseed);
    if( !(m_rctr <= MaxReseed) )
      throw InvalidArgumentException("Unable to generate bytes from hmac drbg. A reseed is required.");

    /////////////////////////////////////////////////////////
    // Sanity check, Table 2
    /////////////////////////////////////////////////////////
    ASSERT(hsize <= MaxRequest);
    if( !(hsize <= MaxRequest) )
      throw InvalidArgumentException("Unable to generate bytes from hmac drbg. The requested size exceeds the maximum this DRBG can produce.");

    /////////////////////////////////////////////////////////
    // We don't accept additional input, Steps 2 & 3 omitted
    /////////////////////////////////////////////////////////

    try
      {
        /////////////////////////////////////////////////////////
        // Generate bits, Step 4
        /////////////////////////////////////////////////////////
        size_t idx = 0, rem /*remaining*/ = hsize;
        while(rem)
          {
            /////////////////////////////////////////////////////////
            // Update V, Step 4.1
            /////////////////////////////////////////////////////////
            m_hmac.Update(m_v.data(), m_v.size());
            m_hmac.TruncatedFinal(m_v.data(), m_v.size());

            /////////////////////////////////////////////////////////
            // Copy out, Step 4.2 (and 5)
            /////////////////////////////////////////////////////////
            const size_t req = std::min(rem, (size_t)CryptoPP::HMAC<HASH>::DIGESTSIZE);
            ::memcpy(hash+idx, m_v.data(), req);

            idx += req;
            rem -= req;
          }

        /////////////////////////////////////////////////////////
        // Update V, Step 6
        /////////////////////////////////////////////////////////
        m_hmac.Update(m_v.data(), m_v.size());
        m_hmac.TruncatedFinal(m_v.data(), m_v.size());

        /////////////////////////////////////////////////////////
        // Update reseed counter, Step 7
        /////////////////////////////////////////////////////////
        m_rctr++;
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  template <class HASH, class DRBGINFO>
  void HmacImpl<HASH,DRBGINFO>::HmacReseed(const byte* seed, size_t ssize)
  {
    ASSERT(DigestLength == m_v.size());
    ASSERT(DigestLength == m_k.size());

    ASSERT(seed && ssize);
    if(!seed || !ssize)
      throw InvalidArgumentException("Unable to reseed hmac drbg. The seed buffer or size is not valid");

    try
      {
        // To reseed, we use {entropy || additional data}.
        // For this operation, we only need SeedLength (see Section 8.6.7).
        // Additional data optional, but should be present because the
        // setSeed interfaces require bits
        const size_t msize /*seed material size*/ = SeedLength;
        CryptoPP::SecByteBlock material(msize + ssize);

        g_pool.GenerateBlock(material.data(), msize);

        // Copy in the user provided "personalization"
        if(seed && ssize)
          ::memcpy(material.data()+msize, seed, ssize);

        HmacUpdate(material.data(), material.size());
      }
    catch(CryptoPP::Exception& ex)
      {
        m_catastrophic = true;
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  ///////////////////////////////////////////////////////////////
  //////////////////////// Block Ciphers ////////////////////////
  ///////////////////////////////////////////////////////////////

  /**
   * Constructs a secure random number generator (RNG).
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  BlockCipherImpl<CIPHER, MODE, DRBGINFO>::BlockCipherImpl(const std::string& algorithm, const byte* seed, size_t size)
    : SecureRandomImpl(algorithm)
  {
  }

  /**
   * Returns the security level associated with the SecureRandom object. Used
   * by KeyGenerator to determine the appropriate key size for init.
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  unsigned int BlockCipherImpl<CIPHER, MODE, DRBGINFO>::getSecurityLevelImpl() const
  {
    return SecurityLevel;
  }

  /**
   * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  byte* BlockCipherImpl<CIPHER, MODE, DRBGINFO>::generateSeedImpl(unsigned int numBytes)
  {
    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexAutoLock lock(getObjectLock());

    throw std::runtime_error("Not implemented");
  }

  /**
   * Returns the name of the algorithm implemented by this SecureRandom object.
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  std::string BlockCipherImpl<CIPHER, MODE, DRBGINFO>::getAlgorithmImpl() const
  {
    return SecureRandomImpl::getAlgorithmImpl();
  }

  /**
   * Generates a user-specified number of random bytes.
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  void BlockCipherImpl<CIPHER, MODE, DRBGINFO>::nextBytesImpl(byte bytes[], size_t size)
  {
    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexAutoLock lock(getObjectLock());

    throw std::runtime_error("Not implemented");
  }

  /**
   * Reseeds this random object.
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  void BlockCipherImpl<CIPHER, MODE, DRBGINFO>::setSeedImpl(const byte seed[], size_t size)
  {
    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexAutoLock lock(getObjectLock());

    throw std::runtime_error("Not implemented");
  }

  /**
   * Reseeds this random object, using the bytes contained in the given long seed.
   */
  template <class CIPHER, template <class CIPHER> class MODE, class DRBGINFO>
  void BlockCipherImpl<CIPHER, MODE, DRBGINFO>::setSeedImpl(int seed)
  {
    // Has a catastrophic error been encountered previously? Forwarding facing gear is the gate keeper.
    ASSERT(!m_catastrophic);
    if(m_catastrophic)
      throw EncryptionException("A catastrophic error was previously encountered");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexAutoLock lock(getObjectLock());

    throw std::runtime_error("Not implemented");
  }
} // esapi
