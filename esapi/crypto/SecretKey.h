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
#include "crypto/Key.h"
#include "crypto/Crypto++Common.h"
#include "util/SecureArray.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

/**
 * This class implements functionality similar to Java's SecretKey for
 * consistency and simplifed porting from ESAPI for Java code.
 */
namespace esapi
{
  class ESAPI_EXPORT SecretKey : public Key
  {
    // For comparisons in the outside world, such as the self tests.
    friend ESAPI_TEST_EXPORT bool operator==(const SecretKey&, const SecretKey&);
    friend ESAPI_TEST_EXPORT bool operator!=(const SecretKey&, const SecretKey&);
    // For dumping keys. Use with care.
    friend ESAPI_TEST_EXPORT std::ostream& operator<<(std::ostream&, const SecretKey&);
    // From KeyDerivationFunction,cpp, which couphs up a SecretKey.
    friend class KeyDerivationFunction;
    // From KeyGeneration.cpp, which couphs up a SecretKey
    friend class KeyGenerator;

  public:
    /**
     * Returns the standard algorithm name for this key.
     */
    virtual std::string getAlgorithm() const;

    /**
     * Returns the name of the primary encoding format of this key, or
     * an a reference to an empty string if this key does not support encoding.
     * The primary encoding format is named in terms of the appropriate ASN.1
     * data format, if an ASN.1 specification for this key exists. When no
     * encoding exists, a reference to the string "RAW" should be returned.
     */
    virtual std::string getFormat() const;

    /**
     * Returns the key in its primary encoding format, or an empty array
     * if this key does not support encoding.
     */
    virtual SecureByteArray getEncoded() const;

    // TODO: testing - remove me
    SecretKey() : m_algorithm(), m_secBlock(), m_format() { }

  /**
   * Not for general consumption. To derive a SecretKey from a secret value, use KeyDerivationFunction.
   * To generate a SecretKey with a specified algorithm, use the KeyGenerator class.
   */
  protected:
    /**
     * Create a random SecretKey of 'size' bytes using a SecureRandom generator
     * specified by algorithm. This should be hidden and tagged ESAPI_PRIVATE,
     * but the test files need it.
     */
    SecretKey(const std::string& alg, const size_t sizeInBytes, const std::string& format = "RAW");
    /**
     * Create a SecretKey from a Crypto++ SecByteBlock. This should be hidden and 
     * tagged ESAPI_PRIVATE, but the test files need it.
     */
    SecretKey(const std::string& alg, const CryptoPP::SecByteBlock& bytes, const std::string& format = "RAW");

  public:
    /**
     * Standard destructor
     */
    virtual ~SecretKey();

    /**
     * Copy a SecretKey
     */
    SecretKey(const SecretKey& rhs);

    /**
     * Assign a SecretKey
     */
    SecretKey& operator=(const SecretKey& rhs);

    /**
     * Returns the size of a SecretKey in bytes
     */
    size_t sizeInBytes() const;

  protected:
    // Hold overs from Crypto++ SecByteBlock.
    ESAPI_PRIVATE const byte* BytePtr() const;

  private:    
    std::string m_algorithm;            // Standard name for crypto algorithm
    CryptoPP::SecByteBlock m_secBlock;    // The actual secret key
    std::string m_format;               // Encoding format
  };

  ESAPI_EXPORT bool operator==(const SecretKey& lhs, const SecretKey& rhs);
  ESAPI_EXPORT bool operator!=(const SecretKey& lhs, const SecretKey& rhs);

  ESAPI_EXPORT std::ostream& operator<<(std::ostream& os, const SecretKey& rhs);

} // NAMESPACE esapi
