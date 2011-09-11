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
#include "crypto/MessageDigestImpl.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace esapi
{
  MessageDigestImpl* MessageDigestImpl::createInstance(const std::string& algorithm)
  {
    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html

#if defined(CRYPTOPP_ENABLE_NAMESPACE_WEAK)
    if(algorithm == "MD5")
      return new MessageDigestTmpl<CryptoPP::Weak::MD5>(algorithm);
#endif

    if(algorithm == "SHA-1")
      return new MessageDigestTmpl<CryptoPP::SHA1>(algorithm);

    if(algorithm == "SHA-224")
      return new MessageDigestTmpl<CryptoPP::SHA224>(algorithm);

    if(algorithm == "SHA-256")
      return new MessageDigestTmpl<CryptoPP::SHA256>(algorithm);

    if(algorithm == "SHA-384")
      return new MessageDigestTmpl<CryptoPP::SHA384>(algorithm);

    if(algorithm == "SHA-512")
      return new MessageDigestTmpl<CryptoPP::SHA512>(algorithm);

    if(algorithm == "Whirlpool")
      return new MessageDigestTmpl<CryptoPP::Whirlpool>(algorithm);

    ///////////////////////////////// Catch All /////////////////////////////////

    // This Java program will throw a NoSuchAlgorithmException
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance("Foo");
    // md.update(scratch);

    // We only have InvalidArgumentException and EncryptionException
    std::ostringstream oss;
    oss << "Algorithm \'" << algorithm << "\' is not supported";
    throw esapi::NoSuchAlgorithmException(oss.str());
  }

  template <class HASH>
  MessageDigestTmpl<HASH>::MessageDigestTmpl(const std::string& algorithm)
    : MessageDigestImpl(algorithm), m_hash()
  {
    ASSERT( !algorithm.empty() );
  }

  /**
   * Returns a string that identifies the algorithm, independent of implementation details.
   */
  template <class HASH>
  std::string MessageDigestTmpl<HASH>::getAlgorithmImpl() const   
  {
    return MessageDigestImpl::getAlgorithmImpl();
  }

  /**
   * Returns a string that identifies the algorithm, independent of implementation details.
   */
  template <class HASH>
  size_t MessageDigestTmpl<HASH>::getDigestLengthImpl() const   
  {
    size_t size;

    try
      {
        size = (size_t)m_hash.DigestSize();
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }

    return size;
  }

  /**
   * Returns a string that identifies the algorithm, independent of implementation details.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::resetImpl()   
  {
    try
      {
        m_hash.Restart();
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }
  }

  /**
   * Updates the digest using the specified byte.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::updateImpl(byte input)   
  {
    m_hash.Update(&input, 1);
  }

  /**
   * Updates the digest using the specified array of bytes.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::updateImpl(const SecureByteArray& input)   
  {
    updateImpl(input.data(), input.size());
  }

  /**
   * Updates the digest using the specified array of bytes.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::updateImpl(const std::string& input)   
  {
    updateImpl((const byte*)input.data(), input.size());
  }

  /**
   * Updates the digest using the specified array of bytes.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::updateImpl(const byte input[], size_t size)   
  {
    //ASSERT(input);
    //ASSERT(size);

    updateImpl(input, size, 0, size);
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::updateImpl(const SecureByteArray& input, size_t offset, size_t len)   
  {
    return updateImpl(input.data(), input.size(), offset, len);
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   */
  template <class HASH>
  void MessageDigestTmpl<HASH>::updateImpl(const byte input[], size_t size, size_t offset, size_t len)   
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
    * Completes the hash computation by performing final operations such as padding. The digest
    * is reset after this call is made. 
   */
   template <class HASH>
   SecureByteArray MessageDigestTmpl<HASH>::digestImpl()
   {
     SecureByteArray out(HASH::DIGESTSIZE);

    try
      {
        // TruncatedFinal returns the requested number of bytes and restarts the hash.
        m_hash.TruncatedFinal(out.data(), out.size());
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }

     return out;
   }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   */
   template <class HASH>
   SecureByteArray MessageDigestTmpl<HASH>::digestImpl(const SecureByteArray& input)
   {
     return digestImpl(input.data(), input.size());
   }

  /**
   * Performs a final update on the digest using the specified string, then completes the
   * digest computation.
   */
   template <class HASH>
   SecureByteArray MessageDigestTmpl<HASH>::digestImpl(const std::string& input)
   {
     return digestImpl((const byte*)input.data(), input.size());
   }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   */
   template <class HASH>
   SecureByteArray MessageDigestTmpl<HASH>::digestImpl(const byte input[], size_t size)
   {
     ASSERT(input);
     ASSERT(size);

     SecureByteArray out(HASH::DIGESTSIZE);

    try
      {
        // Pointer wrap?
        SafeInt<size_t> safe1((size_t)input);
        safe1 += size;

        // TruncatedFinal returns the requested number of bytes and restarts the hash.
        m_hash.TruncatedFinal(out.data(), out.size());
      }
    catch(SafeIntException&)
      {
        throw EncryptionException("Integer overflow detected");
      }
    catch(CryptoPP::Exception& ex)
      {
        throw EncryptionException(std::string("Internal error: ") + ex.what());
      }

     return out;
   }

  /**
   * Completes the hash computation by performing final operations such as padding.
   */
  template <class HASH>
  size_t MessageDigestTmpl<HASH>::digestImpl(SecureByteArray& buf, size_t offset, size_t len)
   
  {
    ASSERT(buf.size());

    return digestImpl(buf.data(), buf.size(), offset, len);
  }

  /**
   * Completes the hash computation by performing final operations such as padding.
   */
  template <class HASH>
  size_t MessageDigestTmpl<HASH>::digestImpl(byte buf[], size_t size, size_t offset, size_t len)
   
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

    if(size < (size_t)m_hash.DigestSize() || len < (size_t)m_hash.DigestSize())
      {
        std::ostringstream oss;
        oss << "Length must be at least " << m_hash.DigestSize() << " for " << getAlgorithmImpl();
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

    return (size_t)req;
  }

  // Explicit instantiations
  template class MessageDigestTmpl<CryptoPP::Weak::MD5>;
  template class MessageDigestTmpl<CryptoPP::SHA1>;
  template class MessageDigestTmpl<CryptoPP::SHA224>;
  template class MessageDigestTmpl<CryptoPP::SHA256>;
  template class MessageDigestTmpl<CryptoPP::SHA384>;
  template class MessageDigestTmpl<CryptoPP::SHA512>;
  template class MessageDigestTmpl<CryptoPP::Whirlpool>;
};

