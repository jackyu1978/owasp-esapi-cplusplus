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

ESAPI_MS_WARNING_PUSH(3)
#include <cryptopp/secblock.h>
ESAPI_MS_WARNING_POP()

/**
 * This class implements functionality similar to Java's SecretKey for
 * consistency and simplifed porting from ESAPI for Java code.
 */
namespace esapi
{
  class ESAPI_EXPORT SecretKey : public Key
  {
    // For comparisons in the outside world, such as the self tests
    friend ESAPI_EXPORT bool operator==(const SecretKey&, const SecretKey&);
    friend ESAPI_EXPORT bool operator!=(const SecretKey&, const SecretKey&);
    // For dumping keys. Use with care
    friend ESAPI_EXPORT std::ostream& operator<<(std::ostream&, const SecretKey&);
    // From KeyDerivationFunction,cpp, which couphs up a SecretKey
    friend class KeyDerivationFunction;
    // From KeyGeneration.cpp, which couphs up a SecretKey
    friend class KeyGenerator;
    template <class CIPHER> friend class StreamCipherGenerator;
    template <class HASH> friend class HmacGenerator;
    template <class HASH> friend class HashGenerator;
    template <class CIPHER, template <class CIPHER> class MODE> friend class BlockCipherGenerator;

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
     * Returns the key in its primary encoding format, or nullptr
     * if this key does not support encoding.
     */
    virtual const byte* getEncoded() const;

  /**
   * Not for general consumption. To derive a SecretKey from a secret value, use KeyDerivationFunction.
   * To generate a SecretKey with a specified algorithm, use KeyGenerator::generateKey();
   */
  protected:
    /**
     * Create a random SecretKey of 'size' bytes using the
     * SecureRandom::GlobalSecureRandom() generator (ANSI X9.31/AES). This
     * should be hidden and tagged ESAPI_PRIVATE, but the test files need it
     * (and we can't work around with preprocessor tricks without a new macro).
     */
    SecretKey(const std::string& alg, const size_t sizeInBytes, const std::string& format = "RAW");
    /**
     * Create a SecretKey from a Crypto++ SecByteBlock
     * This should be hidden and tagged ESAPI_PRIVATE, but the test files need it
     * (and we can't work around with preprocessor tricks without a new macro).
     */
    SecretKey(const std::string& alg, const CryptoPP::SecByteBlock& bytes, const std::string& format = "RAW");

  public:
    /**
     * Standard destructor
     */
    virtual ~SecretKey();

  public:
    SecretKey(const SecretKey& rhs);
    SecretKey& operator=(const SecretKey& rhs);

    size_t sizeInBytes() const;

  protected:
    // Hold overs from Crypto++ SecByteBlock.
    ESAPI_PRIVATE const byte* BytePtr() const;

  private:    
    std::string m_algorithm;            // Standard name for crypto algorithm
    CryptoPP::SecByteBlock secBlock;    // The actual secret key
    std::string m_format;               // Encoding format

  };

  ESAPI_EXPORT bool operator==(const SecretKey& lhs, const SecretKey& rhs);
  ESAPI_EXPORT bool operator!=(const SecretKey& lhs, const SecretKey& rhs);

  ESAPI_EXPORT std::ostream& operator<<(std::ostream& os, const SecretKey& rhs);

}; // NAMESPACE esapi
