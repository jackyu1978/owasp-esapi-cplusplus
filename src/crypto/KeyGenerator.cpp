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
#include "crypto/KeyGenerator.h"
#include "crypto/SecureRandom.h"
#include "crypto/SecretKey.h"
#include "errors/EncryptionException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

ESAPI_MS_WARNING_PUSH(3)
#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/salsa.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/camellia.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>
ESAPI_MS_WARNING_POP()

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/arc4.h>

/**
* This class implements functionality similar to Java's KeyGenerator for consistency
* http://download.oracle.com/javase/6/docs/api/javax/crypto/KeyGenerator.html
*/

namespace esapi
{
  ////////////////////////// Block Ciphers //////////////////////////

  template <class CIPHER, template <class CIPHER> class MODE>
  void BlockCipherGenerator<CIPHER, MODE>::init(unsigned int keyBits)
  {
    ASSERT(keyBits != NoKeySize);
    ASSERT(keyBits < MaxKeySize); 

    // SetKeyBits will throw if any funny business goes on
    setKeySize(keyBits);

    // The global generator is Crypto++'s ANSI X.931/AES
    SecureRandom& prng = SecureRandom::GlobalSecureRandom();

    // Crypto++ magic
    size_t ksize = CIPHER::DEFAULT_KEYLENGTH;
    size_t bsize = CIPHER::BLOCKSIZE;

    // See if we can match security levels. The short of this is, "if the 
    // requested key size is greater than the default key length, use the
    // cipher's maximum key length". If the requested key size is less than
    // the default key length, we use the cipher's default key length.
    if(getKeySize() > ksize)
      ksize = m_encryptor.MaxKeyLength();

    CryptoPP::SecByteBlock seed(ksize+bsize);

    // Initialize the generator
    prng.nextBytes(seed.BytePtr(), seed.SizeInBytes());
    m_encryptor.SetKeyWithIV(seed.BytePtr(), ksize, seed.BytePtr()+ksize);    
  }

  // Sad, but true. CIPER does not always cough up its name
  template <class CIPHER, template <class CIPHER> class MODE>
  BlockCipherGenerator<CIPHER, MODE>::BlockCipherGenerator(const std::string& algorithm)
    : KeyGenerator(algorithm)
  {
    ASSERT( !algorithm.empty() );
  }

  // Called by base class KeyGenerator::getInstance
  template <class CIPHER, template <class CIPHER> class MODE>
  KeyGenerator* BlockCipherGenerator<CIPHER, MODE>::createInstance(const std::string& algorithm)
  {
    return new BlockCipherGenerator<CIPHER, MODE>(algorithm);
  }

  template <class CIPHER, template <class CIPHER> class MODE>
  SecretKey BlockCipherGenerator<CIPHER, MODE>::generateKey()
  {
    // If the block cipher is not resynchronizable, we will generate the same key bits
    ASSERT( m_encryptor.IsResynchronizable() );
    if( !m_encryptor.IsResynchronizable() )
    {
      throw EncryptionException("Failed to resynchronize block cipher");
    }

    // The global generator is Crypto++'s ANSI X.931/AES
    SecureRandom& prng = SecureRandom::GlobalSecureRandom();

    CryptoPP::SecByteBlock iv(CIPHER::BLOCKSIZE);
    prng.nextBytes(iv.BytePtr(), iv.SizeInBytes());

    m_encryptor.Resynchronize(iv.BytePtr(), (int)iv.SizeInBytes());

    // getKeySize() will verify init() has been called
    const unsigned int keyBytes = getKeySize();

    // The SecByteBlock is initialized to a null vector. Encrypt the null
    // vector, and return the result to the caller as the SecretKey.
    CryptoPP::SecByteBlock key(keyBytes);

    // We use a StreamTransformationFilter since it will handle details such as
    // PKCS5 padding (as required)
    CryptoPP::StreamTransformationFilter filter(m_encryptor);
    filter.PutMessageEnd(key.BytePtr(), key.SizeInBytes());

    // MaxRetrievable returns an lword, which is 64 bits.
    const unsigned int ret = (unsigned int)filter.MaxRetrievable();
    ASSERT(ret >= keyBytes);
    if( !(ret >= keyBytes) )
    {
      std::ostringstream oss;
      oss << "Failed to generate the requested " << keyBytes << " bits of material.";
      throw EncryptionException(oss.str());
    }

    filter.Get(key.BytePtr(), key.SizeInBytes());
    return SecretKey(getAlgorithm(), key);
  }

  ////////////////////////// Hashes //////////////////////////

  // Sad, but true. CIPER does not always cough up its name
  template <class HASH>
  HashGenerator<HASH>::HashGenerator(const std::string& algorithm)
    : KeyGenerator(algorithm)
  {
    ASSERT( !algorithm.empty() );
  }

  // Called by base class KeyGenerator::getInstance
  template <class HASH>
  KeyGenerator* HashGenerator<HASH>::createInstance(const std::string& algorithm)
  {
    return new HashGenerator<HASH>(algorithm);
  }

  template <class HASH>
  SecretKey HashGenerator<HASH>::generateKey()
  {
    // getKeySize() will verify init() has been called
    const unsigned int keyBytes = getKeySize();

    // Returned to caller
    CryptoPP::SecByteBlock key(keyBytes);

    // Scratch
    CryptoPP::SecByteBlock hash(HASH::DIGESTSIZE);

    // Initial seed of the hash stream
    // The global generator is Crypto++'s ANSI X.931/AES
    SecureRandom& prng = SecureRandom::GlobalSecureRandom();
    prng.nextBytes(hash.BytePtr(), hash.SizeInBytes());

    size_t idx = 0;
    unsigned int remaining = keyBytes;
    while(remaining)
    {
      HASH hasher;
      const unsigned int req = (unsigned int)std::min(remaining, (unsigned int)HASH::DIGESTSIZE);

      // Initial or previous hash result
      hasher.Update(hash.BytePtr(), hash.SizeInBytes());

      // Though we continually call TruncatedFinal, we are retrieving a
      // full block except for possibly the last block
      hasher.TruncatedFinal(hash.BytePtr(), req);

      // Copy out to key
      ESAPI_MS_NO_WARNING(4996);
      std::copy(hash.BytePtr(), hash.BytePtr()+req, key.BytePtr()+idx);
      ESAPI_MS_DEF_WARNING(4996);

      // Book keeping
      idx += req;
      remaining -= req;
    }

    return SecretKey(getAlgorithm(), key);
  }

  ////////////////////////// Hashes //////////////////////////

  // Sad, but true. CIPER does not always cough up its name
  template <class HASH>
  HmacGenerator<HASH>::HmacGenerator(const std::string& algorithm)
    : KeyGenerator(algorithm)
  {
    ASSERT( !algorithm.empty() );
  }

  // Called by base class KeyGenerator::getInstance
  template <class HASH>
  KeyGenerator* HmacGenerator<HASH>::createInstance(const std::string& algorithm)
  {
    return new HmacGenerator<HASH>(algorithm);
  }

  template <class HASH>
  SecretKey HmacGenerator<HASH>::generateKey()
  {
    // getKeySize() will verify init() has been called
    const unsigned int keyBytes = getKeySize();

    // Returned to caller
    CryptoPP::SecByteBlock key(keyBytes);

    // Scratch
    CryptoPP::SecByteBlock hash(HASH::DIGESTSIZE);

    // The global generator is Crypto++'s ANSI X.931/AES
    SecureRandom& prng = SecureRandom::GlobalSecureRandom();
    prng.nextBytes(hash.BytePtr(), hash.SizeInBytes());

    // Key the HASH
    CryptoPP::HMAC<HASH> hasher(hash.BytePtr(), hash.SizeInBytes());

    // Initial seed of the hash stream
    prng.nextBytes(hash.BytePtr(), hash.SizeInBytes());

    size_t idx = 0;
    size_t remaining = keyBytes;
    while(remaining)
    {
      hasher.Restart();
      const size_t req = std::min(remaining, (size_t)HASH::DIGESTSIZE);

      // Initial or previous hash result
      hasher.Update(hash.BytePtr(), hash.SizeInBytes());

      // Though we continually call TruncatedFinal, we are retrieving a
      // full block except for possibly the last block
      hasher.TruncatedFinal(hash.BytePtr(), req);

      // Copy out to key
      ESAPI_MS_NO_WARNING(4996)
        std::copy(hash.BytePtr(), hash.BytePtr()+req, key.BytePtr()+idx);
      ESAPI_MS_DEF_WARNING(4996)

        // Book keeping
        idx += req;
      remaining -= req;
    }

    return SecretKey(getAlgorithm(), key);
  }

  ////////////////////////// Hashes //////////////////////////

  // Sad, but true. CIPER does not always cough up its name
  template <class CIPHER>
  StreamCipherGenerator<CIPHER>::StreamCipherGenerator(const std::string& algorithm)
    : KeyGenerator(algorithm)
  {
    ASSERT( !algorithm.empty() );
  }

  // Called by base class KeyGenerator::getInstance
  template <class CIPHER>
  KeyGenerator* StreamCipherGenerator<CIPHER>::createInstance(const std::string& algorithm)
  {
    return new StreamCipherGenerator<CIPHER>(algorithm);
  }

  template <class CIPHER>
  SecretKey StreamCipherGenerator<CIPHER>::generateKey()
  {
    // getKeySize() will verify init() has been called
    const unsigned int keyBytes = getKeySize();

    // Returned to caller
    CryptoPP::SecByteBlock key(keyBytes);

    // The global generator is Crypto++'s ANSI X.931/AES
    SecureRandom& prng = SecureRandom::GlobalSecureRandom();
    prng.nextBytes(key.BytePtr(), key.SizeInBytes());

    // Crypto++ discards bytes from the key stream in the case of RC4. See
    // http://www.cryptopp.com/docs/ref/arc4_8cpp_source.html, line 50.
    CIPHER stream(key.BytePtr(), key.SizeInBytes());
    stream.ProcessString(key.BytePtr(), key.SizeInBytes());

    return SecretKey(getAlgorithm(), key);
  }

  ////////////////////////// Base Class (KeyGenerator) //////////////////////////

  const std::string KeyGenerator::DefaultAlgorithm = "AES/OFB";
  const unsigned int KeyGenerator::DefaultKeySize = 128;

  const unsigned int KeyGenerator::NoKeySize = static_cast<unsigned int>(-1);
  const unsigned int KeyGenerator::MaxKeySize = static_cast<unsigned int>(-1) - 8;

  // Default implementation for derived classes which do nothing
  void KeyGenerator::init(unsigned int keyBits)
  {
    ASSERT(keyBits != NoKeySize);
    ASSERT(keyBits < MaxKeySize); 

    // SetKeyBits will throw if any funny business goes on
    setKeySize(keyBits);
  }

  // Single testing point to ensure init() has been called. All derived
  // classes *must* call verifyKeySize() in their generateKey().
  void KeyGenerator::verifyKeySize() const
  {
    // generateKey() must be implemented by all derived classes. The two checks below
    // are common to all derived classes. However, the base class' defualt behavior
    // is to throw to ensure no one is using its generator. Hence, all test must be
    // duplicated in all derived classes.
    ASSERT( m_keyBits != NoKeySize );
    ASSERT( m_keyBits < MaxKeySize );

    if( m_keyBits == NoKeySize )
      throw EncryptionException("Key size (in bits) is not valid.");

    if( !(m_keyBits < MaxKeySize) )
    {
      std::ostringstream oss;
      oss << "Key size (in bits) must be less than " << MaxKeySize << ".";
      throw EncryptionException(oss.str());
    }
  }

  // Default implementation throws to ensure a default key is not used
  SecretKey KeyGenerator::generateKey()
  {
    throw EncryptionException("Using the default KeyGenerator::generateKey");

    ESAPI_MS_NO_WARNING(4702);
    return SecretKey("Error", 0, "Error");
    ESAPI_MS_DEF_WARNING(4702);
  }

  void KeyGenerator::setKeySize(unsigned int keyBits)
  {
    ASSERT( keyBits != NoKeySize );
    ASSERT( keyBits < MaxKeySize );

    // Sanity check (10K is arbitrary)
    ASSERT( keyBits < 8192 + 2048 );

    if( keyBits == NoKeySize )
      throw EncryptionException("Key size (in bits) is not valid.");

    if( !(keyBits < MaxKeySize) )
    {
      std::ostringstream oss;
      oss << "Key size (in bits) must be less than " << MaxKeySize << ".";
      throw EncryptionException(oss.str());
    }

    m_keyBits = keyBits;
  }

  // Called by derived classes to fetch key bytes (not bits)
  unsigned int KeyGenerator::getKeySize() const
  {
    // Single testing point to ensure init() has been called. All
    // generateKey() methods must call the function.
    KeyGenerator::verifyKeySize();

    // SafeInt will throw on wrap
    const unsigned int keyBytes = (unsigned int)((SafeInt<unsigned int>(m_keyBits) + 7) / 8);
    return keyBytes;
  }

  // Default implementation for derived classes which do nothing
  std::string KeyGenerator::getAlgorithm() const
  {
    return m_algorithm;
  }

  KeyGenerator* KeyGenerator::getInstance(const std::string& algorithm)
  {
    ASSERT(!algorithm.empty());

    std::string alg = algorithm, mode;
    std::string::size_type pos;

    // Cut out whitespace
    std::string::iterator it = std::remove_if(alg.begin(), alg.end(), ::isspace);
    if(it != alg.end())
      alg.erase(it, alg.end());

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

    if(alg == "aes" && mode == "cbc")
      return BlockCipherGenerator<CryptoPP::AES, CryptoPP::CBC_Mode>::createInstance("AES/CBC");

    if(alg == "aes" && mode == "cfb")
      return BlockCipherGenerator<CryptoPP::AES, CryptoPP::CFB_Mode>::createInstance("AES/CFB");

    if(alg == "aes" && mode == "ofb")
      return BlockCipherGenerator<CryptoPP::AES, CryptoPP::OFB_Mode>::createInstance("AES/OFB");

    if(alg == "aes" && mode == "")
      return BlockCipherGenerator<CryptoPP::AES, CryptoPP::OFB_Mode>::createInstance("AES");

    if(alg == "camellia" && mode == "cbc")
      return BlockCipherGenerator<CryptoPP::Camellia, CryptoPP::CBC_Mode>::createInstance("Camellia/CBC");

    if(alg == "camellia" && mode == "cfb")
      return BlockCipherGenerator<CryptoPP::Camellia, CryptoPP::CFB_Mode>::createInstance("Camellia/CFB");

    if(alg == "camellia" && mode == "ofb")
      return BlockCipherGenerator<CryptoPP::Camellia, CryptoPP::OFB_Mode>::createInstance("Camellia/OFB");

    if(alg == "camellia" && mode == "")
      return BlockCipherGenerator<CryptoPP::Camellia, CryptoPP::OFB_Mode>::createInstance("Camellia");

    if(alg == "blowfish" && mode == "cbc")
      return BlockCipherGenerator<CryptoPP::Blowfish, CryptoPP::CBC_Mode>::createInstance("Blowfis/CBC");

    if(alg == "blowfish" && mode == "cfb")
      return BlockCipherGenerator<CryptoPP::Blowfish, CryptoPP::CFB_Mode>::createInstance("Blowfis/CFB");

    if(alg == "blowfish" && mode == "ofb")
      return BlockCipherGenerator<CryptoPP::Blowfish, CryptoPP::OFB_Mode>::createInstance("Blowfis/OFB");

    if(alg == "blowfish" && mode == "")
      return BlockCipherGenerator<CryptoPP::Blowfish, CryptoPP::OFB_Mode>::createInstance("Blowfish");

    if(alg == "desede" && mode == "cbc")
      return BlockCipherGenerator<CryptoPP::DES_EDE3, CryptoPP::CBC_Mode>::createInstance("DESede/CBC");

    if(alg == "desede" && mode == "cfb")
      return BlockCipherGenerator<CryptoPP::DES_EDE3, CryptoPP::CFB_Mode>::createInstance("DESede/CFB");

    if(alg == "desede" && mode == "ofb")
      return BlockCipherGenerator<CryptoPP::DES_EDE3, CryptoPP::OFB_Mode>::createInstance("DESede/OFB");

    if(alg == "desede" && mode == "")
      return BlockCipherGenerator<CryptoPP::DES_EDE3, CryptoPP::OFB_Mode>::createInstance("DESede");

    ////////////////////////////////// Hashes //////////////////////////////////

    if(alg == "sha-1" || alg == "sha1" || alg == "sha")
      return HashGenerator<CryptoPP::SHA1>::createInstance("SHA-1");

    if(alg == "sha-224" || alg == "sha224")
      return HashGenerator<CryptoPP::SHA224>::createInstance("SHA-224");

    if(alg == "sha-256" || alg == "sha256")
      return HashGenerator<CryptoPP::SHA256>::createInstance("SHA-256");

    if(alg == "sha-384" || alg == "sha384")
      return HashGenerator<CryptoPP::SHA384>::createInstance("SHA-384");

    if(alg == "sha-512" || alg == "sha512")
      return HashGenerator<CryptoPP::SHA512>::createInstance("SHA-512");

    if(alg == "whirlpool")
      return HashGenerator<CryptoPP::Whirlpool>::createInstance("Whirlpool");

    ////////////////////////////////// HASHs //////////////////////////////////

    if(alg == "hmacsha-1" || alg == "hmacsha1" || alg == "hmacsha")
      return HmacGenerator<CryptoPP::SHA1>::createInstance("HmacSHA1");

    if(alg == "hmacsha-224" || alg == "hmacsha224")
      return HmacGenerator<CryptoPP::SHA1>::createInstance("HmacSHA224");

    if(alg == "hmacsha-256" || alg == "hmacsha256")
      return HmacGenerator<CryptoPP::SHA1>::createInstance("HmacSHA256");

    if(alg == "hmacsha-384" || alg == "hmacsha384")
      return HmacGenerator<CryptoPP::SHA1>::createInstance("HmacSHA384");

    if(alg == "hmacsha-512" || alg == "hmacsha512")
      return HmacGenerator<CryptoPP::SHA1>::createInstance("HmacSHA512");

    if(alg == "hmacwhirlpool")
      return HmacGenerator<CryptoPP::Whirlpool>::createInstance("HmacWhirlpool");

    ////////////////////////////// Stream Ciphers //////////////////////////////

#if defined(CRYPTOPP_ENABLE_NAMESPACE_WEAK)
    if(alg == "arcfour")
      return StreamCipherGenerator<CryptoPP::Weak::ARC4>::createInstance("ARCFOUR");
#endif

    ///////////////////////////////// Catch All /////////////////////////////////

    std::ostringstream oss;
    oss << "Algorithm \'" << algorithm << "\' is not supported.";
    throw EncryptionException(oss.str());
  }

} // NAMESPACE esapi
