/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#pragma once

#include "EsapiCommon.h"
#include "util/NotCopyable.h"
#include "util/SecureArray.h"
#include "util/AlgorithmName.h"
#include "crypto/CryptoppCommon.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"

namespace esapi
{
  // Non-parameterized class so the smart pointer can hold it.
  class ESAPI_PRIVATE MessageDigestBase : private NotCopyable
  {
    // MessageDigest needs access to createInstance()
    friend class MessageDigest;

  public:

    explicit MessageDigestBase(const NarrowString& algorithm)
      : m_algorithm(algorithm) { }

    virtual NarrowString getAlgorithmImpl() const { return m_algorithm.algorithm(); };

    virtual size_t getDigestLengthImpl() const = 0;

    virtual void resetImpl() = 0;

    virtual void updateImpl(byte input) = 0;

    virtual void updateImpl(const byte input[], size_t size) = 0;

    virtual void updateImpl(const SecureByteArray& input) = 0;

    virtual void updateImpl(const NarrowString& input) = 0;

    virtual void updateImpl(const byte input[], size_t size, size_t offset, size_t len) = 0;

    virtual void updateImpl(const SecureByteArray& input, size_t offset, size_t len) = 0;

    virtual SecureByteArray digestImpl() = 0;

    virtual SecureByteArray digestImpl(const byte input[], size_t size) = 0;

    virtual SecureByteArray digestImpl(const SecureByteArray& input) = 0;

    virtual SecureByteArray digestImpl(const NarrowString& input) = 0;

    virtual size_t digestImpl(byte buf[], size_t size, size_t offset, size_t len) = 0;

    virtual size_t digestImpl(SecureByteArray& buf, size_t offset, size_t len) = 0;

  protected:

    static MessageDigestBase* createInstance(const NarrowString& algorithm);

  private:

    // Crypto++ does not always implement AglortihmName()
    AlgorithmName m_algorithm;
  };

  // Parameterized class we actually want.
  template <typename HASH>
    class ESAPI_PRIVATE MessageDigestImpl: public MessageDigestBase
  {
  public:

    explicit MessageDigestImpl(const NarrowString& algorithm);

    virtual NarrowString getAlgorithmImpl() const;

    virtual size_t getDigestLengthImpl() const;

    virtual void resetImpl();

    virtual void updateImpl(byte input);

    virtual void updateImpl(const byte input[], size_t size);

    virtual void updateImpl(const SecureByteArray& input);

    virtual void updateImpl(const NarrowString& input);

    virtual void updateImpl(const byte input[], size_t size, size_t offset, size_t len);

    virtual void updateImpl(const SecureByteArray& input, size_t offset, size_t len);

    virtual SecureByteArray digestImpl();

    virtual SecureByteArray digestImpl(const byte input[], size_t size);

    virtual SecureByteArray digestImpl(const SecureByteArray& input);

    virtual SecureByteArray digestImpl(const NarrowString& input);

    virtual size_t digestImpl(byte buf[], size_t size, size_t offset, size_t len);

    virtual size_t digestImpl(SecureByteArray& buf, size_t offset, size_t len);

  private:

    HASH m_hash;
  };
} // NAMESPACE
