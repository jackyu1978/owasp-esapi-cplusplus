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
#include "crypto/Crypto++Common.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

namespace esapi
{
  // Non-parameterized class so the smart pointer can hold it.
  class ESAPI_PRIVATE MessageDigestImpl : private NotCopyable
  {
    // SecureRandom needs access to createInstance()
    friend class MessageDigest;

  public:

    explicit MessageDigestImpl(const std::string& algorithm)
      : m_algorithm(algorithm) { }

    virtual std::string getAlgorithmImpl() const { return m_algorithm; };

    virtual size_t getDigestLengthImpl() const throw() = 0;

    virtual void resetImpl() = 0;

    virtual void updateImpl(byte input) = 0;

    virtual void updateImpl(const byte input[], size_t size) = 0;

    virtual void updateImpl(const byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException) = 0;

    // virtual byte[] digest(byte input[], size_t size);

    virtual size_t digestImpl(byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException) = 0;

  protected:

    static MessageDigestImpl* MessageDigestImpl::createInstance(const std::string& algorithm)
      throw(InvalidArgumentException);

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

    virtual std::string getAlgorithmImpl() const;

    virtual size_t getDigestLengthImpl() const throw();

    virtual void resetImpl();

    virtual void updateImpl(byte input);

    virtual void updateImpl(const byte input[], size_t size);

    virtual void updateImpl(const byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException);

    // virtual byte[] digest(byte input[], size_t size);

    virtual size_t digestImpl(byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException);

  private:

    HASH m_hash;
  };

  // Force instantiations
  static MessageDigestTmpl<CryptoPP::Weak::MD5> dummy1("MD5");
  static MessageDigestTmpl<CryptoPP::SHA1> dummy2("SHA-1");
  static MessageDigestTmpl<CryptoPP::SHA224> dummy3("SHA-224");
  static MessageDigestTmpl<CryptoPP::SHA256> dummy4("SHA-256");
  static MessageDigestTmpl<CryptoPP::SHA384> dummy5("SHA-384");
  static MessageDigestTmpl<CryptoPP::SHA512> dummy6("SHA-512");
  static MessageDigestTmpl<CryptoPP::Whirlpool> dummy7("Whirlpool");

} // NAMESPACE
