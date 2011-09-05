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
#include "crypto/Crypto++Common.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"

namespace esapi
{
  // Non-parameterized class so the smart pointer can hold it.
  class ESAPI_PRIVATE MessageDigestImpl : private NotCopyable
  {
    // MessageDigest needs access to createInstance()
    friend class MessageDigest;

  public:

    explicit MessageDigestImpl(const std::string& algorithm)
      : m_algorithm(algorithm) { }

    virtual std::string getAlgorithmImpl() const { return m_algorithm; };

    virtual size_t getDigestLengthImpl() const = 0;

    virtual void resetImpl() = 0;

    virtual void updateImpl(byte input) = 0;

    virtual void updateImpl(const byte input[], size_t size) = 0;

    virtual void updateImpl(const SecureByteArray& input) = 0;

    virtual void updateImpl(const byte input[], size_t size, size_t offset, size_t len) = 0;

    virtual void updateImpl(const SecureByteArray& input, size_t offset, size_t len) = 0;

    virtual SecureByteArray digestImpl() = 0;

    virtual SecureByteArray digestImpl(const byte input[], size_t size) = 0;

    virtual SecureByteArray digestImpl(const SecureByteArray& input) = 0;

    virtual size_t digestImpl(byte buf[], size_t size, size_t offset, size_t len) = 0;

    virtual size_t digestImpl(SecureByteArray& buf, size_t offset, size_t len) = 0;

  protected:

    static MessageDigestImpl* createInstance(const std::string& algorithm);

  private:

    // Crypto++ does not always implement AglortihmName()
    std::string m_algorithm;
  };

  // Parameterized class we actually want.
  template <typename HASH>
  class ESAPI_PRIVATE MessageDigestTmpl: public MessageDigestImpl
  {
  public:

    explicit MessageDigestTmpl(const std::string& algorithm);

    virtual std::string getAlgorithmImpl() const ;

    virtual size_t getDigestLengthImpl() const;

    virtual void resetImpl();

    virtual void updateImpl(byte input);

    virtual void updateImpl(const byte input[], size_t size);

    virtual void updateImpl(const SecureByteArray& input);

    virtual void updateImpl(const byte input[], size_t size, size_t offset, size_t len);

    virtual void updateImpl(const SecureByteArray& input, size_t offset, size_t len);

    virtual SecureByteArray digestImpl();

    virtual SecureByteArray digestImpl(const byte input[], size_t size);

    virtual SecureByteArray digestImpl(const SecureByteArray& input);

    virtual size_t digestImpl(byte buf[], size_t size, size_t offset, size_t len);

    virtual size_t digestImpl(SecureByteArray& buf, size_t offset, size_t len);

  private:

    HASH m_hash;
  };
} // NAMESPACE
