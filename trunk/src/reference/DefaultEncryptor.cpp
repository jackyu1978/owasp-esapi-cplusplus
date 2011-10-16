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

#include "util/TextConvert.h"
#include "util/SecureArray.h"
// #include "crypto/Cipher.h"
#include "crypto/PlainText.h"
#include "crypto/CipherText.h"
#include "crypto/SecretKey.h"
#include "crypto/CryptoHelper.h"
#include "crypto/MessageDigest.h"
#include "crypto/Crypto++Common.h"
#include "errors/IntegrityException.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"

#include "DummyConfiguration.h"

// Must be consistent with JavaEncryptor.java.
// http://owasp-esapi-java.googlecode.com/svn/trunk/src/main/java/org/owasp/esapi/reference/crypto/JavaEncryptor.java

namespace esapi
{
  // Private to this module (for now)
  static void split(const String& str, const String& delim, StringArray& parts);

  String DefaultEncryptor::DefaultDigestAlgorithm()
  {
    return String(L"SHA-512");
  }

  unsigned int DefaultEncryptor::DefaultDigestIterations()
  {
    return 1024;
  }

  String DefaultEncryptor::hash(const String &message, const String &salt, unsigned int iterations) const
  { 
    MessageDigest md(DefaultDigestAlgorithm());
    const size_t size = md.getDigestLength();
    SecureByteArray hash(size);

    DummyConfiguration config;
    const SecureByteArray& msalt = config.getMasterSalt();
    if( !msalt.empty() )
      {
        md.update(msalt.data(), msalt.size());
      }    

    if( !salt.empty() )
      {
        SecureByteArray sa = TextConvert::GetBytes(salt, "UTF-8");
        md.update(sa.data(), sa.size());
      }    

    if( !message.empty() )
      {
        SecureByteArray ma = TextConvert::GetBytes(message, "UTF-8");
        md.update(ma.data(), ma.size());
      }

    // Fetch the hash (resets the object)
    md.digest(hash.data(), hash.size(), 0, size);

    for (unsigned int i = 0; i < iterations; i++)
      {
        md.update(hash.data(), hash.size());
        md.digest(hash.data(), hash.size(), 0, hash.size());
      }

    NarrowString encoded;
    try
      {
        CryptoPP::ArraySource(hash.data(), hash.size(), true /* don't buffer */,
          new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encoded), false /* no line breaks */));
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }

    return TextConvert::NarrowToWide(encoded);
  }

  CipherText DefaultEncryptor::encrypt(const PlainText& plainText) const
  {
    DummyConfiguration config;
    SecretKey key("Unknown", config.getMasterKey());

    return encrypt(key, plainText);
  }

  CipherText DefaultEncryptor::encrypt(const SecretKey& secretKey, const PlainText& plainText) const
  {
    DummyConfiguration config;

    StringArray parts;
    String xform = config.getCipherTransformation();    
    split(xform, L"\\/:", parts);

    ESAPI_ASSERT2(parts.size() == 3, "Malformed cipher transformation: " + TextConvert::WideToNarrow(xform));
    if(parts.size() != 3)
      throw EncryptionException("Malformed cipher transformation: " + TextConvert::WideToNarrow(xform));

    const String mode = parts[1];
    bool allowed = CryptoHelper::isAllowedCipherMode(mode);

    ESAPI_ASSERT2(allowed, NarrowString("Cipher mode '") + TextConvert::WideToNarrow(mode) + "' is not allowed");
    if( !allowed )
      throw EncryptionException(NarrowString("Cipher mode '") + TextConvert::WideToNarrow(mode) + "' is not allowed");    

    // Cipher encrypter = Cipher::getInstance(xform);
    // String cipherAlg = encrypter.getAlgorithm();
    //int keyLen = config.getEncryptionKeyLength();

    bool overwrite = config.overwritePlainText();
    size_t keyBits = secretKey.getEncoded().length() * 8;

    return CipherText();
  }

  void split(const String& str, const String& delim, StringArray& parts)
  {
    String s(str);
    String::size_type pos = 0;

    while( (pos = s.find_first_of(delim)) != String::npos )
      {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos+1);
      }

    // Catch any tail bytes
    if( !s.empty() )
      parts.push_back(s);
  }
}

