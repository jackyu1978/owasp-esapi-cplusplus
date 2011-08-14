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

#include "crypto/PlainText.h"
#include "crypto/CipherText.h"
#include "crypto/SecretKey.h"
#include "crypto/MessageDigest.h"

#include <string>
#include <memory>

ESAPI_MS_WARNING_PUSH(3)
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
ESAPI_MS_WARNING_POP()

// auto_ptr is deprecated, and causes boat loads of warnings
// on GCC 4.6. A silent cockpit is a safe cockpit. We use a define
// rather than a typedef to avoid the template arguments here.
#if defined(ESAPI_CPLUSPLUS_UNIQUE_PTR)
# define THE_AUTO_PTR  std::unique_ptr
#else
# define THE_AUTO_PTR  std::auto_ptr
#endif

// Must be consistent with JavaEncryptor.java.
// http://owasp-esapi-java.googlecode.com/svn/trunk/src/main/java/org/owasp/esapi/reference/crypto/JavaEncryptor.java

namespace esapi
{
  std::string DefaultEncryptor::DefaultDigestAlgorithm = "SHA-512";
  unsigned int DefaultEncryptor::DefaultDigestIterations = 1024;

  std::string DefaultEncryptor::hash(const std::string &message, const std::string &salt, unsigned int iterations) throw(EncryptionException)
  {      
    THE_AUTO_PTR<MessageDigest> md(MessageDigest::getInstance(DefaultDigestAlgorithm));
    const size_t size = md->getDigestLength();
    THE_AUTO_PTR<byte> hash(new byte[size]);

    // Initial updates
    md->update((const byte*)salt.data(), salt.size());
    md->update((const byte*)message.data(), message.size());    

    // Fetch the hash (resets the object)
    md->digest(hash.get(), size, 0, size);

    for (unsigned int i = 0; i < iterations; i++)
    {
      md->update(hash.get(), size);
      md->digest(hash.get(), size, 0, size);
    }

    std::string encoded;
    try
    {
      CryptoPP::ArraySource(hash.get(), size, true /* don't buffer */, new CryptoPP::Base64Encoder(
          new CryptoPP::StringSink(encoded), false /* no line breaks */));
    }
    catch(CryptoPP::Exception& ex)
    {
      throw EncryptionException(std::string("Internal error: ") + ex.what());
    }

    return encoded;
  }
}
