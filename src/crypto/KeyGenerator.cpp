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
  KeyGenerator::KeyGenerator(const std::string& algorithmName)
    : m_random(SecureRandom::getInstance(algorithmName)), m_keyBytes((unsigned)InvalidKeyBytes)
  {
  }

  /**
  * Copy a KeyGenerator object (SecureRandom is safe to copy).
  */
  KeyGenerator::KeyGenerator(const KeyGenerator& rhs)
    : m_random(rhs.m_random), m_keyBytes(rhs.m_keyBytes)
  {
  }

  /**
  * Assign a KeyGenerator object (SecureRandom is safe to copy).
  */
  KeyGenerator& KeyGenerator::operator=(const KeyGenerator& rhs)
  {
    if(this != &rhs)
    {
      m_random = rhs.m_random;
      m_keyBytes = rhs.m_keyBytes;
    }

    return *this;
  }

  /**
  * Returns a KeyGenerator object that generates secret keys for the specified algorithm.
  */
  KeyGenerator KeyGenerator::getInstance(const std::string& algorithm)
  {
    ASSERT( !algorithm.empty() );
    return KeyGenerator(algorithm);
  }

  /**
  * Returns the default algorithm used for key generation. Keep this value synchronized
  * with DefaultKeySize(). SP800-90 offers the mappings of security bits to generators
  * Table 2 (p.34) and Table 3 (p. 46) and SP800-57.
  */
  std::string KeyGenerator::DefaultAlgorithm()
  {
    return "SHA-256";
  }

  /**
  * Returns the default algorithm used for key generation. Keep this value synchronized
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
    ESAPI_ASSERT2(m_keyBytes <= m_random.getSecurityLevel(),
      "Requested bytes exceeds the security level of the generator");
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
    ESAPI_ASSERT2(m_keyBytes <= m_random.getSecurityLevel(),
      "Requested bytes exceeds the security level of the generator");   
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
  std::string KeyGenerator::getAlgorithm() const
  {
    return m_random.getAlgorithm();
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
    ASSERT(m_keyBytes <= m_random.getSecurityLevel());

    CryptoPP::SecByteBlock key(m_keyBytes);
    m_random.nextBytes(key.data(), key.size());

    return SecretKey(m_random.getAlgorithm(), key);
  }

} // NAMESPACE esapi
