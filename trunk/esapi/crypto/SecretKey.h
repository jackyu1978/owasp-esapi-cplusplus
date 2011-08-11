/*
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
  // Forward declarations for circular dependencies
  class KeyDerivationFunction;

  class SecretKey : public Key
  {
    // For comparisons in the outside world, such as the self tests
    friend bool operator==(const SecretKey&, const SecretKey&);
    friend bool operator!=(const SecretKey&, const SecretKey&);
    // For dumping keys. Use with care
    friend std::ostream& operator<<(std::ostream&, const SecretKey&);
    // For internal routines and duties
    friend class KeyDerivationFunction;

  public:
    /**
     * Create a random SecretKey of 'size' bytes using the
     * SecureRandom::GlobalSecureRandom() generator (ANSI X9.31/AES).
     */
    SecretKey(const std::string& alg, const size_t size, const std::string& format = "RAW");
    /**
     * Create a SecretKey from a Crypto++ SecByteBlock
     */
    SecretKey(const std::string& alg, const CryptoPP::SecByteBlock& bytes, const std::string& format = "RAW");

    /*
     * Standard destructor
     */
    virtual ~SecretKey();
        
  public:
    /**
     * Returns the standard algorithm name for this key.
     */
    virtual const std::string& getAlgorithm() const;

    /**
     * Returns the name of the primary encoding format of this key, or
     * an a reference to an empty string if this key does not support encoding.
     * The primary encoding format is named in terms of the appropriate ASN.1
     * data format, if an ASN.1 specification for this key exists. When no
     * encoding exists, a reference to the string "RAW" should be returned.
     */
    virtual const std::string& getFormat() const;

    /**
     * Returns the key in its primary encoding format, or nullptr
     * if this key does not support encoding.
     */
    virtual const byte* getEncoded() const;

  public:
    // kww - Small thing, but copy CTOR and assignment operator operate on RHS,
    // not LHS. Changed here and in .cpp file.
    SecretKey(const SecretKey& rhs);
    SecretKey& operator=(const SecretKey& rhs);

    size_t sizeInBytes() const;

  protected:
    // Hold overs from Crypto++ SecByteBlock.
    const byte* BytePtr() const;

  private:
    std::string m_algorithm;            // Standard name for crypto algorithm
    CryptoPP::SecByteBlock secBlock;    // The actual secret key
    std::string m_format;               // Encoding format

  };

  bool operator==(const SecretKey& lhs, const SecretKey& rhs);
  bool operator!=(const SecretKey& lhs, const SecretKey& rhs);

  std::ostream& operator<<(std::ostream& os, const SecretKey& rhs);

}; // NAMESPACE esapi
