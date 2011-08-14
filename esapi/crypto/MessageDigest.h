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

#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

#include <string>
#include <vector>

namespace esapi
{

  class ESAPI_EXPORT MessageDigest
  {
  public:

    // Default hash algorithm, currently returns SHA-256
    static const std::string DefaultAlgorithm;

    // Standard factory method
    static MessageDigest* getInstance(const std::string& algorithm = DefaultAlgorithm) throw(InvalidArgumentException);

    // Standard name of the hash
    virtual std::string getAlgorithm() const throw();

    // Digest size
    virtual unsigned int getDigestLength() const throw() = 0;

    // Resets the digest
    virtual void reset() = 0;

    // Input to the hash
    virtual void update(byte input) = 0;
    virtual void update(const byte input[], size_t size) = 0;
    virtual void update(const std::vector<byte>& input) = 0;
    virtual void update(const byte input[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException) = 0;

    // Hash calculation
    // virtual byte[] digest(byte input[], size_t size) = 0;
    virtual unsigned int digest(std::vector<byte>& buf, size_t offset, size_t len) = 0;
    virtual unsigned int digest(byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException) = 0;

    // CTORs and DTORs are very important for MS DLLs
  private:
    ESAPI_PRIVATE MessageDigest() { /* No external instantiations */ }
  protected:
    ESAPI_PRIVATE explicit MessageDigest(const std::string& algorithmName)
      : m_algorithm(algorithmName) { /* No external instantiations */ }
  public:
    virtual ~MessageDigest() { }

  private:
    std::string m_algorithm;
  };

  /////////////////////// Concrete Implementation ///////////////////////
  template <class HASH>
    class MessageDigestImpl: public MessageDigest
  {
    // Base class needs access to protected createInstance in derived class
    friend MessageDigest* MessageDigest::getInstance(const std::string&) throw(InvalidArgumentException);

  public:

    /**
     * Returns the length of the digest in bytes.
     */
    virtual unsigned int getDigestLength() const throw() { return m_hash.DigestSize(); }

    /**
     * Resets the digest for further use.
     */
    virtual void reset() { m_hash.Restart(); }

    /**
     * Updates the digest using the specified byte.
     *
     * @param input  the specified byte.
     *
     * @throws       throws an EncryptionException if a cryptographic failure occurs.
     */
    virtual void update(byte input);

    /**
     * Updates the digest using the specified array of bytes.
     *
     * @param input  the specified array.
     * @param size   the size fo the array.
     *
     * @throws       throws an EncryptionException if the array or size is not valid
     *               or a cryptographic failure occurs.
     */
    virtual void update(const byte input[], size_t size);

    /**
     * Updates the digest using the specified array of bytes.
     *
     * @param input  the specified byte array.
     *
     * @throws       throws an EncryptionException if the array or size is not valid
     *               or a cryptographic failure occurs.
     */
    virtual void update(const std::vector<byte>& input);

    /**
     * Updates the digest using the specified array of bytes, starting at the specified offset.
     *
     * @param input  the specified array.
     * @param size   the size of the array.
     * @param offset the offset into the array.
     * @param len    the length of data to digest.
     *
     * @throws       throws an EncryptionException if the array or size is not valid,
     *               offset and len exceeds the array's bounds, or a cryptographic
     *               failure occurs.
     */
    virtual void update(const byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException);

    /**
     * Performs a final update on the digest using the specified array of bytes, then completes the
     * digest computation.
     *
     * @param buf    the output buffer for the computed digest.
     * @param offset the offset into the output buffer to begin storing the digest.
     * @param len    the number of bytes within buf allotted for the digest.
     */
    // virtual byte[] digest(byte input[], size_t size);

    /**
     * Completes the hash computation by performing final operations such as padding.
     *
     * @param buf    the output buffer for the computed digest.
     * @param size   the size of the output buffer.
     * @param offset offset into the output buffer to begin storing the digest.
     * @param len    number of bytes within buf allotted for the digest.
     *
     * @return       the number of digest bytes written to buf.
     */
    virtual unsigned int digest(byte buf[], size_t size, size_t offset, size_t len)
      throw(InvalidArgumentException, EncryptionException);

    /**
     * Completes the hash computation by performing final operations such as padding.
     *
     * @param buf    the output buffer for the computed digest.
     * @param offset offset into the output buffer to begin storing the digest.
     * @param len    number of bytes within buf allotted for the digest.
     *
     * @return       the number of digest bytes written to buf.
     */
    virtual unsigned int digest(std::vector<byte>& buf, size_t offset, size_t len);

  protected:
    // Called by base class MessageDigest::getInstance
    ESAPI_PRIVATE static MessageDigest* createInstance(const std::string& algorithm);

    // Sad, but true. HASH does not always cough up its name
    ESAPI_PRIVATE explicit MessageDigestImpl(const std::string& algorithm);

    // CTORs and DTORs are very important for MS DLLs
  private:
    ESAPI_PRIVATE MessageDigestImpl() { /* No external instantiations */ }
  public:
    virtual ~MessageDigestImpl() { }

  private:
    HASH m_hash;
  };

} // NAMESPACE
