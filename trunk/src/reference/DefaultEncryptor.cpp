/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "reference/DefaultEncryptor.h"

#include "crypto/Cipher.h"
#include "crypto/PlainText.h"
#include "crypto/CipherText.h"
#include "crypto/SecretKey.h"
#include "crypto/MessageDigest.h"
#include "crypto/CryptoHelper.h"
#include "util/SecureArray.h"

#include "DummyConfiguration.h"

#include <string>

// Must be consistent with JavaEncryptor.java.
// http://owasp-esapi-java.googlecode.com/svn/trunk/src/main/java/org/owasp/esapi/reference/crypto/JavaEncryptor.java

namespace esapi
{
  // Private to this module (for now)
  static void split(const std::string& str, const std::string& delim, std::vector<std::string>& parts);

  std::string DefaultEncryptor::DefaultDigestAlgorithm()
  {
    return std::string("SHA-512");
  }

  unsigned int DefaultEncryptor::DefaultDigestIterations()
  {
    return 1024;
  }

  std::string DefaultEncryptor::hash(const std::string &message, const std::string &salt, unsigned int iterations)
  {      
    MessageDigest md(DefaultDigestAlgorithm());
    const size_t size = md.getDigestLength();
    SecureByteArray hash(size);

    // Initial updates
    md.update((const byte*)salt.data(), salt.size());
    md.update((const byte*)message.data(), message.size());

    // Fetch the hash (resets the object)
    md.digest(hash.data(), hash.size(), 0, size);

    for (unsigned int i = 0; i < iterations; i++)
      {
        md.update(hash.data(), hash.size());
        md.digest(hash.data(), hash.size(), 0, size);
      }

    std::string encoded;
    try
      {
        CryptoPP::ArraySource(hash.data(), hash.size(), true /* don't buffer */,
          new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded), false /* no line breaks */));
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }

    return encoded;
  }

  CipherText DefaultEncryptor::encrypt(const PlainText& plainText)
  {
    DummyConfiguration config;
    SecretKey key("Unknown", config.getMasterKey());

    return encrypt(key, plainText);
  }

  CipherText DefaultEncryptor::encrypt(const SecretKey& secretKey, const PlainText& plainText)
  {
    DummyConfiguration config;

    std::vector<std::string> parts;
    std::string xform = config.getCipherTransformation();    
    split(xform, "\\/:", parts);

    ESAPI_ASSERT2(parts.size() == 3, "Malformed cipher transformation: " + xform);
    if(parts.size() != 3)
      throw EncryptionException("Malformed cipher transformation: " + xform);

    const std::string mode = parts[1];
    bool allowed = CryptoHelper::isAllowedCipherMode(mode);

    ESAPI_ASSERT2(allowed, std::string("Cipher mode '") + mode + "' is not allowed");
    if( !allowed )
      throw EncryptionException(std::string("Cipher mode '") + mode + "' is not allowed");    

    Cipher encrypter = Cipher::getInstance(xform);
    String cipherAlg = encrypter.getAlgorithm();
    //int keyLen = config.getEncryptionKeyLength();

    bool overwrite = config.overwritePlainText();
    size_t keyBits = secretKey.getEncoded().length() * 8;

    return CipherText();
  }

  void split(const std::string& str, const std::string& delim, std::vector<std::string>& parts)
  {
    std::string s(str);
    std::string::size_type pos = 0;

    while( (pos = s.find_first_of(delim)) != std::string::npos )
      {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos+1);
      }

    // Catch any tail bytes
    if( !s.empty() )
      parts.push_back(s);
  }
}

