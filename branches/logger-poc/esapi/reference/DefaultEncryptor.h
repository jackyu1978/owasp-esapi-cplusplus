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

// Must be consistent with JavaEncryptor.java.
// http://owasp-esapi-java.googlecode.com/svn/trunk/src/main/java/org/owasp/esapi/reference/crypto/JavaEncryptor.java

#include "EsapiCommon.h"
#include "Encryptor.h"
#include "crypto/SecretKey.h"
#include "crypto/PlainText.h"
#include "crypto/CipherText.h"

namespace esapi
{

  class ESAPI_EXPORT DefaultEncryptor : public Encryptor
  {
  public:

    static NarrowString DefaultDigestAlgorithm();
    static unsigned int DefaultDigestIterations();

  public:

    /**
     * {@inheritDoc}
     * 
     * Hashes the data using the algorithm from the JavaEncryptor class. This method first adds the master salt,
     * then the user provided salt, and finally the password. The digested data is rehashed the specified number of iterations
     * in order to help strengthen weak passwords. Internally, the plainText and Salt are converted to UTF-8 strings.
     */
    // orig 2012.01.29 jAHOLMES  (inexact match class still abstract)
    // virtual String hash(const NarrowString& plainText, const NarrowString &salt, unsigned int iterations = DefaultDigestIterations()) const;
    virtual NarrowString hash(const NarrowString& plainText, const NarrowString &salt, unsigned int iterations = 4096 ) const;

    virtual CipherText encrypt(const PlainText& plainText) const;

    virtual CipherText encrypt(const SecretKey& secretKey, const PlainText& plainText) const;

    virtual PlainText decrypt(const CipherText& /*cipherText*/) const
    {
      return PlainText();
    }

    virtual PlainText decrypt(const SecretKey& secretKey, const CipherText& /*cipherText*/) const
    {
      return PlainText();
    }

    virtual NarrowString sign(const NarrowString & /*message*/) const
    {
      return String();
    }

    virtual bool verifySignature(const NarrowString &, const NarrowString &) const
    {
      return false;
    }

    // orig 2012.01.29 jAHOLMES  (inexact match class still abstract)
    // virtual String seal(const NarrowString &, long) const
    virtual NarrowString seal(const NarrowString &, time_t) const
    {
      return String();
    }

    virtual NarrowString unseal(const NarrowString &) const
    {
      return String();
    }

    virtual bool verifySeal(const NarrowString &) const
    {
      return false;
    }

    // orig 2012.01.29 jAHOLMES  (inexact match class still abstract)
    // virtual long getRelativeTimeStamp(long /*timeStamp*/) const
    virtual long getRelativeTimeStamp(time_t /*timeStamp*/) const
    {
      return 0;
    }

    virtual long getTimeStamp() const
    {
      return 0;
    }

  public:
    explicit DefaultEncryptor() { }
    virtual ~DefaultEncryptor() { }

  private:
    // Follow the lead of the base class
    DefaultEncryptor& operator=(const DefaultEncryptor& rhs);
  };
} // NAMESPACE

