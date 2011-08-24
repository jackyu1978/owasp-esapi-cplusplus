/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "EsapiCommon.h"
#include "crypto/MessageDigest.h"
#include "crypto/Crypto++Common.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace esapi
{
  std::string MessageDigest::DefaultAlgorithm()
  {
    return "SHA-256";
  }

  MessageDigest* MessageDigest::getInstance(const std::string& algorithm) throw(InvalidArgumentException)
  {
    ASSERT(!algorithm.empty());

    std::string alg = algorithm;

    // Cut out whitespace
    std::string::iterator it = std::remove_if(alg.begin(), alg.end(), ::isspace);
    if(it != alg.end())
      alg.erase(it, alg.end());

    // Normalize the case
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html

    /////////////////////////////////// Factory ///////////////////////////////////

#if defined(CRYPTOPP_ENABLE_NAMESPACE_WEAK)
    if(alg == "md5" || alg == "md-5")
      return MessageDigestImpl<CryptoPP::Weak::MD5>::createInstance("MD5");
#endif

    if(alg == "sha1" || alg == "sha1")
      return MessageDigestImpl<CryptoPP::SHA1>::createInstance("SHA-1");

    if(alg == "sha224" || alg == "sha-224")
      return MessageDigestImpl<CryptoPP::SHA224>::createInstance("SHA-224");

    if(alg == "sha256" || alg == "sha-256")
      return MessageDigestImpl<CryptoPP::SHA256>::createInstance("SHA-256");

    if(alg == "sha384" || alg == "sha-384")
      return MessageDigestImpl<CryptoPP::SHA384>::createInstance("SHA-384");

    if(alg == "sha512" || alg == "sha-512")
      return MessageDigestImpl<CryptoPP::SHA512>::createInstance("SHA-512");

    if(alg == "whirlpool")
      return MessageDigestImpl<CryptoPP::Whirlpool>::createInstance("Whirlpool");

    ///////////////////////////////// Catch All /////////////////////////////////

    // This Java program will throw a NoSuchAlgorithmException
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance("Foo");
    // md.update(scratch);

    // We only have InvalidArgumentException and EncryptionException
    std::ostringstream oss;
    oss << "Algorithm \'" << algorithm << "\' is not supported.";
    throw InvalidArgumentException(oss.str());
  }

  // Default implementation for derived classes which do nothing
  std::string MessageDigest::getAlgorithm() const throw()
  {
    return m_algorithm;
  }

  /////////////////////// Concrete Implementation ///////////////////////

  // Sad, but true. HASH does not always cough up its name
  template <class HASH>
  MessageDigestImpl<HASH>::MessageDigestImpl(const std::string& algorithm)
    : MessageDigest(algorithm)
  {
    ASSERT( !algorithm.empty() );
  }

  // Called by base class MessageDigest::getInstance
  template <class HASH>
  MessageDigest* MessageDigestImpl<HASH>::createInstance(const std::string& algorithm)
  {
    return new MessageDigestImpl<HASH>(algorithm);
  }

  /**
   * Updates the digest using the specified byte.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::update(byte input)
  {
    m_hash.Update(&input, 1);
  }

  /**
   * Updates the digest using the specified array of bytes. 
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::update(const byte input[], size_t size)
  {
    //ASSERT(input);
    //ASSERT(size);

    update(input, size, 0, size);
  }

  /**
   * Updates the digest using the specified array of bytes.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::update(const std::vector<byte>& input)
  {
    ASSERT( !input.empty() );

    update(&input[0], input.size());
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::update(const byte input[], size_t size, size_t offset, size_t len)
    throw(InvalidArgumentException, EncryptionException)
  {
    ASSERT(input);
    //ASSERT(size);

    // This Java program will throw a NullPointerException
    // byte[] scratch = null;
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // md.update(scratch);

    // This Java program is OK
    // byte[] scratch = new byte[0];
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // md.update(scratch);

    // NOT: if(!input || !size)
    if(!input)
      throw InvalidArgumentException("The input array or size is not valid");

    // This Java program will throw an IllegalArgumentException
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // md.update(scratch, 1, 16);

    try
      {
        // Pointer wrap?
        SafeInt<size_t> safe1((size_t)input);
        safe1 += size;

        // Within bounds?
        SafeInt<size_t> safe2(offset);
        safe2 += len;
        if((size_t)safe2 > size)
          throw InvalidArgumentException("The buffer is too small for the specified offset and length");

        m_hash.Update(input+offset, len);
      }
    catch(SafeIntException&)
      {
        throw EncryptionException("Integer overflow detected");
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   */
  // template <class HASH>
  // byte[] MessageDigestImpl<HASH>::digest(byte input[], size_t size)
  // {
  // }

  /**
   * Completes the hash computation by performing final operations such as padding.
   */
  template <class HASH>
  unsigned int MessageDigestImpl<HASH>::digest(byte buf[], size_t size, size_t offset, size_t len)
    throw(InvalidArgumentException, EncryptionException)
  {
    ASSERT(buf);
    ASSERT(size);

    // This Java program will throw an IllegalArgumentException
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // int size = md.digest(null, 0, 0);

    if(!buf || !size)
      throw InvalidArgumentException("The buffer array or size is not valid");

    // This Java program will throw an DigestException
    // byte[] scratch = new byte[1];
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // int size = md.digest(scratch, 0, 0);

    // And so will this one
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // int ret = md.digest(scratch, 0, 15);

    if(size < (unsigned int)m_hash.DigestSize() || len < (unsigned int)m_hash.DigestSize())
      {
        std::ostringstream oss;
        oss << "Length must be at least " << m_hash.DigestSize() << " for " << getAlgorithm();
        throw InvalidArgumentException(oss.str());
      }

    const size_t req = std::min(size, std::min((size_t)HASH::DIGESTSIZE, len));

    try
      {
        // Pointer wrap?
        SafeInt<size_t> safe1((size_t)buf);
        safe1 += size;

        // Within bounds?
        SafeInt<size_t> safe2(offset);
        safe2 += len;
        if((size_t)safe2 > size)
          throw InvalidArgumentException("The buffer is too small for the specified offset and length");

        // TruncatedFinal returns the requested number of bytes and restarts the hash.
        m_hash.TruncatedFinal(buf+offset, req);
      }
    catch(SafeIntException&)
      {
        throw EncryptionException("Integer overflow detected");
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }

    return req;
  }

  /**
   * Completes the hash computation by performing final operations such as padding.
   */
  template <class HASH>
  unsigned int  MessageDigestImpl<HASH>::digest(std::vector<byte>& buf, size_t offset, size_t len)
  {
    ASSERT( !buf.empty() );
    return digest(&buf[0], buf.size(), offset, len);
  }
}
