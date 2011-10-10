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
#include "util/TextConvert.h"
#include "util/AlgorithmName.h"
#include "crypto/MessageDigest.h"
#include "crypto/MessageDigestImpl.h"
#include "crypto/Crypto++Common.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"

#include "safeint/SafeInt3.hpp"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace esapi
{
  // Forward declaration
  template <typename HASH> class MessageDigestImpl;

  String MessageDigest::DefaultAlgorithm()
  {
    return String(L"SHA-256");
  }

  /**
   * Creates a message digest with the specified algorithm name.
   */
  MessageDigest::MessageDigest(const String& algorithm)   
    : m_lock(new Mutex),
      m_impl(MessageDigestBase::createInstance(AlgorithmName::normalizeAlgorithm(algorithm)))
  {
    ASSERT( !algorithm.empty() );
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);
  }

  /**
   * Creates a MessageDigest from an implmentation
   */
  MessageDigest::MessageDigest(MessageDigestBase* impl)
    : m_lock(new Mutex), m_impl(impl)
  {
    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);
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

    if(this != &rhs)
      {
        m_lock = rhs.m_lock;
        m_impl = rhs.m_impl;
      }

    ASSERT(m_lock.get() != nullptr);
    ASSERT(m_impl.get() != nullptr);

    return *this;
  }

  MessageDigest MessageDigest::getInstance(const NarrowString& algorithm)   
  {
    ASSERT(!algorithm.empty());
    return getInstance(TextConvert::NarrowToWide(algorithm));
  }

  MessageDigest MessageDigest::getInstance(const String& algorithm)   
  {
    ASSERT(!algorithm.empty());

    const String alg(AlgorithmName::normalizeAlgorithm(algorithm));
    MessageDigestBase* impl = MessageDigestBase::createInstance(alg);
    MEMORY_BARRIER();

    ASSERT(impl != nullptr);
    if(impl == nullptr)
      throw EncryptionException("Failed to create MessageDigest");

    return MessageDigest(impl);
  }

  // Default implementation for derived classes which do nothing
  String MessageDigest::getAlgorithm() const
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    if(m_impl.get() == nullptr)
      throw EncryptionException("Failed to retrieve algorithm name");

    return m_impl->getAlgorithmImpl();
  }

  /**
   * Returns the length of the digest in bytes.
   */
  size_t MessageDigest::getDigestLength() const
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->getDigestLengthImpl();
  }

  /**
   * Resets the digest for further use.
   */
  void MessageDigest::reset()
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
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
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
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
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->updateImpl(input, size);
  }

  /**
   * Updates the digest using the specified array of bytes.
   *
   * @param input the specified array.
   *
   * @throws throws an EncryptionException if the array or size is not valid
   * or a cryptographic failure occurs.
   */
  void MessageDigest::update(const SecureByteArray& input)
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->updateImpl(input);
  }

  /**
   * Updates the digest using the specified string.
   *
   * @param input the specified String. Internally, the String is converted
   * to a byte array using TextConvert::GetBytes with a UTF-8 encoding.
   *
   * @throws throws an EncryptionException if the array or size is not valid
   * or a cryptographic failure occurs.
   */
  void MessageDigest::update(const String& str)
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->updateImpl(str);
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   *
   * @param buf the specified array.
   * @param size the size of the array.
   * @param offset the offset into the array.
   * @param len the length of data to digest.
   *
   * @throws throws an EncryptionException if the array or size is not valid,
   * offset and len exceeds the array's bounds, or a cryptographic
   * failure occurs.
   */
  void MessageDigest::update(const byte buf[], size_t size, size_t offset, size_t len)   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->updateImpl(buf, size, offset, len);
  }

  /**
   * Updates the digest using the specified array of bytes, starting at the specified offset.
   *
   * @param buf the specified array.
   * @param offset the offset into the array.
   * @param len the length of data to digest.
   *
   * @throws throws an EncryptionException if the array or size is not valid,
   * offset and len exceeds the array's bounds, or a cryptographic
   * failure occurs.
   */
  void MessageDigest::update(const SecureByteArray& sa, size_t offset, size_t len)   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->updateImpl(sa, offset, len);
  }

  /**
   * Completes the hash computation by performing final operations such as padding. The digest
   * is reset after this call is made. 
   */
  SecureByteArray MessageDigest::digest()
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->digestImpl();
  }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   *
   * @param input the specified array.
   * @param size the size of the array.
   */
  SecureByteArray MessageDigest::digest(const byte input[], size_t size)
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->digestImpl(input, size);
  }

  /**
   * Performs a final update on the digest using the specified array of bytes, then completes the
   * digest computation.
   *
   * @param input the specified array.
   */
  SecureByteArray MessageDigest::digest(const SecureByteArray& input)
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->digestImpl(input);
  }

  /**
   * Performs a final update on the digest using the specified string, then completes the
   * digest computation. Internally, the String is converted to a byte
   * array using TextConvert::GetBytes with a UTF-8 encoding.
   *
   * @param input the specified array.
   */
  SecureByteArray MessageDigest::digest(const String& input)
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->digestImpl(input);
  }

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
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->digestImpl(buf, size, offset, len);
  }

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
  size_t MessageDigest::digest(SecureByteArray& buf, size_t offset, size_t len)   
  {
    // All forward facing gear which manipulates internal state acquires the object lock
    MutexLock lock(getObjectLock());

    ASSERT(m_impl.get() != nullptr);
    return m_impl->digestImpl(buf, offset, len);
  }

  Mutex& MessageDigest::getObjectLock() const
  {
    ASSERT(m_lock.get() != nullptr);
    return *m_lock.get();
  }
}
