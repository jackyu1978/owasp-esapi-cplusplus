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

#include "Encryptor.h"

#include "crypto/PlainText.h"
#include "crypto/CipherText.h"
#include "crypto/SecretKey.h"
#include "crypto/MessageDigest.h"

#include <string>
#include <cstdio>

ESAPI_MS_WARNING_PUSH(3)
#include <cryptopp/filters.h>
ESAPI_MS_WARNING_POP()

namespace esapi
{
  class ESAPI_EXPORT DefaultEncryptor : public Encryptor
  {
    // hashing
    static std::string hashAlgorithm;   // = "SHA-512";
    static unsigned int hashIterations; //  = 1024;

  public:
    virtual std::string hash(const std::string &plaintext, const std::string &salt)
    {
      return hash( plaintext, salt, hashIterations );
    }

    virtual std::string hash(const std::string &plaintext, const std::string &salt, int iterations)
    {
      std::string encoded;

      /*
      MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
      byte bytes[digest::DIGESTSIZE];
      try {
      digest.Update(securityConfiguration().getMasterSalt());
      digest.Update(salt.getBytes(encoding));
      digest.Update(plaintext.getBytes(encoding));

      // rehash a number of times to help strengthen weak passwords
      digest.Final(bytes);
      for (int i = 0; i < iterations; i++) {
      digest.Update(bytes);
      digest.Final(bytes);
      }
      CryptoPP::StringSource(bytes, false, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));

      } catch (NoSuchAlgorithmException& e) {
      throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
      } catch (UnsupportedEncodingException& ex) {
      throw new EncryptionException("Internal error", "Can't find encoding for " + encoding, ex);
      }
      */

      return std::string();
    }

    virtual CipherText encrypt(PlainText)
    {
      return CipherText();
    }

    virtual CipherText encrypt(SecretKey, PlainText)
    {
      return CipherText();
    }

    virtual PlainText decrypt(CipherText)
    {
      return PlainText();
    }

    virtual PlainText decrypt(SecretKey, CipherText)
    {
      return PlainText();
    }

    virtual std::string sign(const std::string &)
    {
      return std::string();
    }

    virtual std::string seal(const std::string &, long)
    {
      return std::string();
    }

    virtual std::string unseal(const std::string &)
    {
      return std::string();
    }

    virtual bool verifyseal(const std::string &)
    {
      return false;
    }

    virtual long getRelativeTimeStamp(long)
    {
      return 0;
    }

    virtual long getTimeStamp()
    {
      return 0;
    }

  };
} // NAMESPACE