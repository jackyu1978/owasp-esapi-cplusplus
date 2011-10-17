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
#include "crypto/SecretKey.h"
#include "crypto/KeyGenerator.h"
#include "crypto/SecureRandom.h"
#include "crypto/Crypto++Common.h"
#include "util/TextConvert.h"
#include "errors/EncryptionException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

/**
* This class implements functionality similar to Java's KeyGenerator for consistency
* http://download.oracle.com/javase/6/docs/api/javax/crypto/KeyGenerator.html
*/

namespace esapi
{
  /**
  * Creates a KeyGenerator object.
  */
  KeyGenerator::KeyGenerator(const NarrowString& algorithmName)
    : m_algorithm(algorithmName, true), m_keyBytes((unsigned)InvalidKeyBytes),
    m_random(SecureRandom::getInstance(SecureRandom::DefaultAlgorithm()))
  {
  }

  /**
  * Copy a KeyGenerator object (SecureRandom is safe to copy).
  */
  KeyGenerator::KeyGenerator(const KeyGenerator& rhs)
    : m_algorithm(rhs.m_algorithm), m_keyBytes(rhs.m_keyBytes),
    m_random(rhs.m_random)
  {
  }

  /**
  * Assign a KeyGenerator object (SecureRandom is safe to copy).
  */
  KeyGenerator& KeyGenerator::operator=(const KeyGenerator& rhs)
  {
    if(this != &rhs)
    {
      m_algorithm = rhs.m_algorithm;
      m_keyBytes = rhs.m_keyBytes;
      m_random = rhs.m_random;      
    }

    return *this;
  }

  /**
  * Returns a KeyGenerator object that generates secret keys for the specified algorithm.
  */
  KeyGenerator KeyGenerator::getInstance(const NarrowString& algorithm)
  {
    ASSERT( !algorithm.empty() );
    KeyGenerator kgen(algorithm);

    // http://download.oracle.com/javase/6/docs/api/javax/crypto/KeyGenerator.html
    // "This class provides the functionality of a secret (symmetric) key generator."
    NarrowString cipher = kgen.getAlgorithm();
    if(cipher != "DES" && cipher != "DES_ede" && cipher != "Blowfish" && cipher != "AES" &&
      cipher != "Camellia" && cipher != "HmacSHA1" && cipher != "HmacSHA224" &&
      cipher != "HmacSHA256" && cipher != "HmacSHA384"&& cipher != "HmacSHA512" &&
      cipher != "HmacWhirlpool" )
    {
      throw NoSuchAlgorithmException(cipher + " KeyGenerator not available");
    }

    return kgen;
  }

  /**
  * Returns a KeyGenerator object that generates secret keys for the specified algorithm.
  */
  KeyGenerator KeyGenerator::getInstance(const String& algorithm)
  {
    ASSERT( !algorithm.empty() );
    return KeyGenerator::getInstance(TextConvert::WideToNarrow(algorithm));
  }

  /**
  * Returns the default algorithm used for key generation. Keep this value synchronized
  * with DefaultKeySize(). SP800-90 offers the mappings of security bits to generators
  * Table 2 (p.34) and Table 3 (p. 46) and SP800-57.
  */
  NarrowString KeyGenerator::DefaultAlgorithm()
  {
    return "AES";
  }

  /**
  * Returns the default security bits for key generation. Keep this value synchronized
  * with DefaultAlgorithm(). SP800-90 offers the mappings of security bits to generators
  * Table 2 (p.34) and Table 3 (p.46) and SP800-57.
  */
  unsigned int KeyGenerator::DefaultKeySize()
  {
    return 128;
  }

  /**
  * Initializes this key generator for a certain keysize.
  */
  void KeyGenerator::init(unsigned int keyBits)
  {
    try
    {
      // Convert bits to bytes
      SafeInt<unsigned int> size(keyBits);

      size += 7;
      size /= 8;

      m_keyBytes = (unsigned int)size;
    }
    catch(SafeIntException&)
    {
      throw EncryptionException("The key size provided is not valid");
    }

    // SecureRandom stashes away the SecurityLevel in bytes (not
    // the customary bits). We should not be generating keys 
    // beyond its security level. Sanity check it now.
    //ESAPI_ASSERT2(m_keyBytes <= m_random.getSecurityLevel(),
    //  "Requested bytes exceeds the security level of the generator");
  }

  /**
  * Initializes this key generator for a certain keysize, using a user-provided source of randomness.
  */
  void KeyGenerator::init(unsigned int keyBits, const SecureRandom& random)
  {
    try
    {
      // Convert bits to bytes
      SafeInt<unsigned int> size(keyBits);

      size += 7;
      size /= 8;

      m_keyBytes = (unsigned int)size;
    }
    catch(SafeIntException&)
    {
      throw EncryptionException("The key size provided is not valid");
    }

    m_random = random;

    // SecureRandom stashes away the SecurityLevel in bytes (not
    // the customary bits). We should not be generating keys 
    // beyond its security level. Sanity check it now.
    //ESAPI_ASSERT2(m_keyBytes <= m_random.getSecurityLevel(),
    //  "Requested bytes exceeds the security level of the generator");   
  }

  /**
  * Initializes this key generator.
  */
  void KeyGenerator::init(const SecureRandom& random)
  {
    m_random = random;
  }

  /**
  * Returns the algorithm name of this KeyGenerator object.
  */
  NarrowString KeyGenerator::getAlgorithm() const
  {
    NarrowString algorithm;
    m_algorithm.getAlgorithm(algorithm);

    return algorithm;
  }

  /**
  * Generates a secret key.
  */
  SecretKey KeyGenerator::generateKey()
  {
    ASSERT(m_keyBytes != (unsigned int)InvalidKeyBytes);
    if(m_keyBytes == (unsigned int)InvalidKeyBytes)
      throw EncryptionException("The key size is not valid");

    // SecureRandom stashes away the SecurityLevel in bytes (not
    // the customary bits). Here, we should not be generating
    // keys beyond its security level.
    ESAPI_ASSERT2(m_keyBytes <= m_random.getSecurityLevel(),
      "The requested number of key bits exceeds the generator's security level");

    CryptoPP::SecByteBlock key(m_keyBytes);
    m_random.nextBytes(key.data(), key.size());

    NarrowString algorithm;
    m_algorithm.getAlgorithm(algorithm);

    return SecretKey(algorithm, key);
  }

} // NAMESPACE esapi

