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
  // Forward declaration
  template <typename HASH> class MessageDigestTmpl;

  std::string MessageDigest::DefaultAlgorithm()
  {
    return std::string("SHA-256");
  }

  /**
  * Creates a message digest with the specified algorithm name.
  */
  MessageDigest::MessageDigest(const std::string& algorithm)
    throw(InvalidArgumentException)
    : m_lock(new Mutex), m_impl(MessageDigestImpl::createInstance(normalizeAlgortihm(algorithm)))
  {
    ASSERT( !algorithm.empty() );
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to create MessageDigest");
  }

  /**
  * Creates a MessageDigest from an implmentation
  */
  MessageDigest::MessageDigest(MessageDigestImpl* impl)
    : m_lock(new Mutex), m_impl(impl)
  {
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to create MessageDigest");
  }

  /**
  * Copies a message digest.
  */
  MessageDigest::MessageDigest(const MessageDigest& rhs)
    : m_lock(rhs.m_lock), m_impl(rhs.m_impl)
  {
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);
  }

  /**
  * Assign a message digest.
  */
  MessageDigest& MessageDigest::operator=(const MessageDigest& rhs)
  {
    // Need to think about this one.... We want to lock 'this' in case
    // someone else is using it. However, MutexLock takes a reference
    // to 'this' object's lock. After the assignment below, the lock
    // has changed (it points to the new object lock). We subsequently
    // release the new lock (not the old lock).
    //boost::shared_ptr<Mutex> tlock(m_lock);
    //ESAPI_ASSERT2(tlock.get() != nullptr, "Object lock is null in assignment");
    //MutexLock lock(*tlock.get());

    if(this != &rhs)
    {
      m_lock = rhs.m_lock;
      m_impl = rhs.m_impl;
    }

    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    return *this;
  }

  MessageDigest MessageDigest::getInstance(const std::string& algorithm) throw(InvalidArgumentException)
  {
    ASSERT(!algorithm.empty());

    const std::string alg(normalizeAlgortihm(algorithm));
    MEMORY_BARRIER();

    if(alg.empty())
    {
      std::ostringstream oss;
      oss << "Algorithm \'" << algorithm << "\' is not supported.";
      throw InvalidArgumentException(oss.str());
    }

    MessageDigestImpl* impl = MessageDigestImpl::createInstance(alg);
    MEMORY_BARRIER();

    ASSERT(impl != nullptr);
    if(impl == nullptr)
      throw EncryptionException("Failed to create MessageDigest");

    return MessageDigest(impl);
  }

  // Default implementation for derived classes which do nothing
  std::string MessageDigest::getAlgorithm() const
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->getAlgorithmImpl();
  }

  /**
  * Returns the length of the digest in bytes.
  */
  size_t MessageDigest::getDigestLength() const
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->getDigestLengthImpl();
  }

  /**
  * Resets the digest for further use.
  */
  void MessageDigest::reset()
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to reset");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->resetImpl();
  }

  /**
  * Updates the digest using the specified byte.
  *
  * @param input the specified byte.
  *
  * @throws throws an EncryptionException if a cryptographic failure occurs.
  */
  void MessageDigest::update(byte input)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to update digest");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->updateImpl(input);
  }

  /**
  * Updates the digest using the specified array of bytes.
  *
  * @param input the specified array.
  * @param size the size fo the array.
  *
  * @throws throws an EncryptionException if the array or size is not valid
  * or a cryptographic failure occurs.
  */
  void MessageDigest::update(const byte input[], size_t size)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to update digest");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->updateImpl(input, size);
  }

  /**
  * Updates the digest using the specified array of bytes, starting at the specified offset.
  *
  * @param input the specified array.
  * @param size the size of the array.
  * @param offset the offset into the array.
  * @param len the length of data to digest.
  *
  * @throws throws an EncryptionException if the array or size is not valid,
  * offset and len exceeds the array's bounds, or a cryptographic
  * failure occurs.
  */
  void MessageDigest::update(const byte buf[], size_t size, size_t offset, size_t len)
    throw(InvalidArgumentException, EncryptionException)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to update digest");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->updateImpl(buf, size, offset, len);
  }

  /**
  * Performs a final update on the digest using the specified array of bytes, then completes the
  * digest computation.
  *
  * @param buf the output buffer for the computed digest.
  * @param offset the offset into the output buffer to begin storing the digest.
  * @param len the number of bytes within buf allotted for the digest.
  */
  // byte[] MessageDigest::digest(byte input[], size_t size);

  /**
  * Completes the hash computation by performing final operations such as padding.
  *
  * @param buf the output buffer for the computed digest.
  * @param size the size of the output buffer.
  * @param offset offset into the output buffer to begin storing the digest.
  * @param len number of bytes within buf allotted for the digest.
  *
  * @return the number of digest bytes written to buf.
  */
  size_t MessageDigest::digest(byte buf[], size_t size, size_t offset, size_t len)
    throw(InvalidArgumentException, EncryptionException)
  {
    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve digest");

    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    return m_impl->digestImpl(buf, size, offset, len);
  }

  Mutex& MessageDigest::getObjectLock() const
  {
    ASSERT(m_lock.get() != nullptr);
    return *m_lock.get();
  }

  /**
  * Normalizes the algorithm name. An empty string on input is interpreted as
  * the default algortihm. If the algorithm is not found (ie, unsupported),
  * return the empty string.
  */
  std::string MessageDigest::normalizeAlgortihm(const std::string& algorithm)
  {
    std::string alg = algorithm;

    // Cut out whitespace
    std::string::iterator it = std::remove_if(alg.begin(), alg.end(), ::isspace);
    if(it != alg.end())
      alg.erase(it, alg.end());

    // Select default algorithm if empty
    if(alg.empty())
      alg = DefaultAlgorithm();

    // Normalize the case
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    if(alg == "md5" || alg == "md-5")
      return "MD5";

    if(alg == "sha-1" || alg == "sha1" || alg == "sha")
      return "SHA-1";

    if(alg == "sha-224" || alg == "sha224")
      return "SHA-224";

    if(alg == "sha-256" || alg == "sha256")
      return "SHA-256";

    if(alg == "sha-384" || alg == "sha384")
      return "SHA-384";

    if(alg == "sha-512" || alg == "sha512")
      return "SHA-512";

    if(alg == "whirlpool")
      return "Whirlpool";

    return "";
  }
}
