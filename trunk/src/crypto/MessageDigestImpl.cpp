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
#include "util/SecureArray.h"
#include "util/TextConvert.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"

#include "safeint/SafeInt3.hpp"

#include <algorithm>

namespace esapi
{
  MessageDigestBase* MessageDigestBase::createInstance(const String& algorithm)
  {
    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html
    ASSERT( !algorithm.empty() );

    if(algorithm == L"MD5")
      return new MessageDigestImpl<CryptoPP::Weak::MD5>(algorithm);

    if(algorithm == L"SHA-1")
      return new MessageDigestImpl<CryptoPP::SHA1>(algorithm);

    if(algorithm == L"SHA-224")
      return new MessageDigestImpl<CryptoPP::SHA224>(algorithm);

    if(algorithm == L"SHA-256")
      return new MessageDigestImpl<CryptoPP::SHA256>(algorithm);

    if(algorithm == L"SHA-384")
      return new MessageDigestImpl<CryptoPP::SHA384>(algorithm);

    if(algorithm == L"SHA-512")
      return new MessageDigestImpl<CryptoPP::SHA512>(algorithm);

    if(algorithm == L"Whirlpool")
      return new MessageDigestImpl<CryptoPP::Whirlpool>(algorithm);

    ///////////////////////////////// Catch All /////////////////////////////////

    // This Java program will throw a NoSuchAlgorithmException
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance(L"Foo");
    // md.update(scratch);

    // We only have IllegalArgumentException and EncryptionException
    std::ostringstream oss;
    oss << "Algorithm \'" << TextConvert::WideToNarrow(algorithm) << "\' is not supported";
    throw NoSuchAlgorithmException(oss.str());
  }

  template <class HASH>
  MessageDigestImpl<HASH>::MessageDigestImpl(const String& algorithm)
    : MessageDigestBase(algorithm), m_hash()
  {
    ASSERT( !algorithm.empty() );
  }

  /**
   * Returns a string that identifies the algorithm, independent of implementation details.
   */
  template <class HASH>
  String MessageDigestImpl<HASH>::getAlgorithmImpl() const   
  {
    return MessageDigestBase::getAlgorithmImpl();
  }

  /**
   * Returns a string that identifies the algorithm, independent of implementation details.
   */
  template <class HASH>
  size_t MessageDigestImpl<HASH>::getDigestLengthImpl() const   
  {
    size_t size;

    try
      {
        size = (size_t)m_hash.DigestSize();
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }

    return size;
  }

  /**
   * Returns a string that identifies the algorithm, independent of implementation details.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::resetImpl()
  {
    try
      {
        m_hash.Restart();
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }
  }

  /**
   * Updates the digest using the specified byte.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::updateImpl(byte input)   
  {
    try
      {
        m_hash.Update(&input, 1);
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }
  }

  /**
   * Updates the digest using the specified array of bytes.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::updateImpl(const SecureByteArray& input)   
  {
    updateImpl(input.data(), input.size());
  }

  /**
   * Updates the digest using the specified string.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::updateImpl(const String& str)   
  {
    // Our String classes do not have a getBytes() method.
    SecureByteArray sa = TextConvert::GetBytes(str, "UTF-8");
    updateImpl(sa.data(), sa.size());
  }

  /**
   * Updates the digest using the specified array of bytes.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::updateImpl(const byte input[], size_t size)   
  {
    //ASSERT(input);
    //ASSERT(size);

    updateImpl(input, size, 0, size);
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::updateImpl(const SecureByteArray& sa, size_t offset, size_t len)   
  {
    //ASSERT(sa.data());
    //ASSERT(sa.size());
    //ASSERT(len);
    //ASSERT(offset+len <= size);

    return updateImpl(sa.data(), sa.size(), offset, len);
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   */
  template <class HASH>
  void MessageDigestImpl<HASH>::updateImpl(const byte input[], size_t size, size_t offset, size_t len)   
  {
    ESAPI_ASSERT2(input, "Input array is not valid");
    ESAPI_ASSERT2(size, "Input array size is 0");
    ESAPI_ASSERT2(len, "Input array length is 0");
    ESAPI_ASSERT2(offset+len <= size, "Input array offset and length exceeds size");

    // This Java program will throw a NullPointerException
    // byte[] scratch = null;
    // MessageDigest md = MessageDigest.getInstance(L"MD5");
    // md.update(scratch);

    // This Java program is OK
    // byte[] scratch = new byte[0];
    // MessageDigest md = MessageDigest.getInstance(L"MD5");
    // md.update(scratch);

    // This Java program will throw an IllegalArgumentException
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance(L"MD5");
    // md.update(scratch, 1, 16);

    // Removed Java like hack on a NULL reference. An empty string will
    // eventually end up here. When its data pointer is retrieved, it will be
    // NULL and its size will be 0 size. We simply can't throw.
    // We don't early out in case the hash updates internal state even on a
    // null or zero size input.
    //if(!input)
    //  throw IllegalArgumentException("The input array or size is not valid");

    try
      {
        // Pointer wrap?
        SafeInt<size_t> safe1((size_t)input);
        safe1 += size;

        // Within array bounds?
        SafeInt<size_t> safe2(offset);
        safe2 += len;
        if((size_t)safe2 > size)
          throw IllegalArgumentException("The buffer is too small for the specified offset and length");

        m_hash.Update(input+offset, len);
      }
    catch(const SafeIntException&)
      {
        throw EncryptionException("Integer overflow detected");
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }
  }

  /**
   * Completes the hash computation by performing final operations such as padding. The digest
   * is reset after this call is made. 
   */
  template <class HASH>
  SecureByteArray MessageDigestImpl<HASH>::digestImpl()
  {
    SecureByteArray digest(HASH::DIGESTSIZE);

    try
      {
        // TruncatedFinal returns the requested number of bytes and restarts the hash.
        m_hash.TruncatedFinal(digest.data(), digest.size());
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }

    return digest;
  }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   */
  template <class HASH>
  SecureByteArray MessageDigestImpl<HASH>::digestImpl(const SecureByteArray& sa)
  {
    //ASSERT(sa.data());
    //ASSERT(sa.size());

    return digestImpl(sa.data(), sa.size());
  }

  /**
   * Performs a final update on the digest using the specified string, then completes the
   * digest computation.
   */
  template <class HASH>
  SecureByteArray MessageDigestImpl<HASH>::digestImpl(const String& input)
  {
    //ASSERT(input.data());
    //ASSERT(input.length());

    // Our String classes do not have a getBytes() method.
    SecureByteArray sa = TextConvert::GetBytes(input, "UTF-8");
    return digestImpl(sa.data(), sa.size());
  }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   */
  template <class HASH>
  SecureByteArray MessageDigestImpl<HASH>::digestImpl(const byte input[], size_t size)
  {
    //ASSERT(input);
    //ASSERT(size);

    SecureByteArray out(HASH::DIGESTSIZE);

    try
      {
        // Pointer wrap?
        SafeInt<size_t> safe1((size_t)input);
        safe1 += size;

        // TruncatedFinal returns the requested number of bytes and restarts the hash.
        m_hash.TruncatedFinal(out.data(), out.size());
      }
    catch(const SafeIntException&)
      {
        throw EncryptionException("Integer overflow detected");
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }

    return out;
  }

  /**
   * Completes the hash computation by performing final operations such as padding.
   */
  template <class HASH>
  size_t MessageDigestImpl<HASH>::digestImpl(SecureByteArray& buf, size_t offset, size_t len)
   
  {
    //ASSERT(buf.data());
    //ASSERT(buf.size());
    //ASSERT(offset + len <= buf.size());

    return digestImpl(buf.data(), buf.size(), offset, len);
  }

  /**
   * Completes the hash computation by performing final operations such as padding.
   */
  template <class HASH>
  size_t MessageDigestImpl<HASH>::digestImpl(byte buf[], size_t size, size_t offset, size_t len)
   
  {
    ESAPI_ASSERT2(buf, "Input array is not valid");
    ESAPI_ASSERT2(size, "Input array size is 0");
    ESAPI_ASSERT2(len, "Input array length is 0");
    ESAPI_ASSERT2(offset+len <= size, "Input array offset and length exceeds size");

    // This Java program will throw an IllegalArgumentException
    // MessageDigest md = MessageDigest.getInstance("MD5");
    // int size = md.digest(null, 0, 0);

    if(!buf || !size)
      throw IllegalArgumentException("The buffer array or size is not valid");

    // This Java program will throw a DigestException
    // byte[] scratch = new byte[1];
    // MessageDigest md = MessageDigest.getInstance(L"MD5");
    // int size = md.digest(scratch, 0, 0);

    // And so will this one
    // byte[] scratch = new byte[16];
    // MessageDigest md = MessageDigest.getInstance(L"MD5");
    // int ret = md.digest(scratch, 0, 15);

    if(size < (size_t)m_hash.DigestSize() || len < (size_t)m_hash.DigestSize())
      {
        std::stringstream oss;
        oss << "Length must be at least " << m_hash.DigestSize() << " for " << TextConvert::WideToNarrow(getAlgorithmImpl());
        throw IllegalArgumentException(oss.str());
      }

    const size_t req = std::min(size, std::min((size_t)HASH::DIGESTSIZE, len));
    ASSERT(req > 0);

    try
      {
        // Pointer wrap?
        SafeInt<size_t> safe1((size_t)buf);
        safe1 += size;

        // Within bounds?
        SafeInt<size_t> safe2(offset);
        safe2 += len;
        if((size_t)safe2 > size)
          throw IllegalArgumentException("The buffer is too small for the specified offset and length");

        // TruncatedFinal returns the requested number of bytes and restarts the hash.
        m_hash.TruncatedFinal(buf+offset, req);
      }
    catch(const SafeIntException&)
      {
        throw EncryptionException("Integer overflow detected");
      }
    catch(const CryptoPP::Exception& ex)
      {
        throw EncryptionException(NarrowString("Internal error: ") + ex.what());
      }

    return (size_t)req;
  }

  // Explicit instantiations
  template class MessageDigestImpl<CryptoPP::Weak::MD5>;
  template class MessageDigestImpl<CryptoPP::SHA1>;
  template class MessageDigestImpl<CryptoPP::SHA224>;
  template class MessageDigestImpl<CryptoPP::SHA256>;
  template class MessageDigestImpl<CryptoPP::SHA384>;
  template class MessageDigestImpl<CryptoPP::SHA512>;
  template class MessageDigestImpl<CryptoPP::Whirlpool>;
};

