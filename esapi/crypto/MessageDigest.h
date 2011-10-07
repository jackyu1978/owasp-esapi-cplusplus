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

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "util/SecureArray.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"

#include <boost/shared_ptr.hpp>

namespace esapi
{
  // Forward declaration
  class MessageDigestImpl;

  class ESAPI_EXPORT MessageDigest
  {
  public:

    /**
    * Returns the default message digest, currently defined as SHA-256.
    */
    static String DefaultAlgorithm();

    /**
    * Returns a MessageDigest object that implements the specified digest algorithm.
    */
    static MessageDigest getInstance(const String& algorithm = DefaultAlgorithm());

    /**
    * Returns a MessageDigest object that implements the specified digest algorithm.
    */
    static MessageDigest getInstance(const NarrowString& algorithm);

    /**
    * Creates a message digest with the specified algorithm name.
    */
    explicit MessageDigest(const String& algorithm = DefaultAlgorithm());

    /**
    * Copies a message digest.
    */
    MessageDigest(const MessageDigest& digest);

    /**
    * Destroy a message digest.
    */
    virtual ~MessageDigest() { };

    /**
    * Assign a message digest.
    */
    MessageDigest& operator=(const MessageDigest& digest);

    /**
    * Returns a string that identifies the algorithm, independent of implementation details.
    */    
    String getAlgorithm() const;

    /**
    * Returns the length of the digest in bytes.
    */
    virtual size_t getDigestLength() const;

    /**
    * Resets the digest for further use.
    */
    virtual void reset();

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
    *
    * @throws       throws an EncryptionException if the array or size is not valid
    *               or a cryptographic failure occurs.
    */
    virtual void update(const SecureByteArray& input);

    /**
    * Updates the digest using the specified string.
    *
    * @param input  the specified string.
    *
    * @throws       throws an EncryptionException if the array or size is not valid
    *               or a cryptographic failure occurs.
    */
    virtual void update(const String& input);

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
    * Updates the digest using the specified array of bytes, starting at the specified offset.
    *
    * @param input  the specified array.
    * @param offset the offset into the array.
    * @param len    the length of data to digest.
    *
    * @throws       throws an EncryptionException if the array or size is not valid,
    *               offset and len exceeds the array's bounds, or a cryptographic
    *               failure occurs.
    */
    virtual void update(const SecureByteArray& input, size_t offset, size_t len);

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
    virtual void update(const byte buf[], size_t size, size_t offset, size_t len);

    /**
    * Completes the hash computation by performing final operations such as padding. The digest
    * is reset after this call is made.   
    */
    virtual SecureByteArray digest();

    /**
    * Performs a final update on the digest using the specified array of bytes, then completes the
    * digest computation.
    *
    * @param input  the specified array.
    * @param size   the size of the array.
    */
    virtual SecureByteArray digest(const SecureByteArray& input);

    /**
    * Performs a final update on the digest using the specified string, then completes the
    * digest computation.
    *
    * @param input  the specified array.
    * @param size   the size of the array.
    */
    virtual SecureByteArray digest(const String& input);

    /**
    * Performs a final update on the digest using the specified array of bytes, then completes the
    * digest computation.
    *
    * @param input  the specified array.
    * @param size   the size of the array.
    */
    virtual SecureByteArray digest(const byte input[], size_t size);

    /**
    * Completes the hash computation by performing final operations such as padding.
    *
    * @param buf    the output buffer for the computed digest.
    * @param offset offset into the output buffer to begin storing the digest.
    * @param len    number of bytes within buf allotted for the digest.
    *
    * @return       the number of digest bytes written to buf.
    */
    virtual size_t digest(SecureByteArray& buf, size_t offset, size_t len);

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
    virtual size_t digest(byte buf[], size_t size, size_t offset, size_t len);

  protected:

    /**
    * Creates a MessageDigest from an implmentation. Used by getInstance(...).
    */
    ESAPI_PRIVATE MessageDigest(MessageDigestImpl* impl);

    /**
     * Retrieves the object level lock
     */
    ESAPI_PRIVATE inline Mutex& getObjectLock() const;

  private:

    /**
     * Object level lock for concurrent access
     */
    mutable boost::shared_ptr<Mutex> m_lock;

    /**
     * Reference counted PIMPL.
     */
    boost::shared_ptr< MessageDigestImpl > m_impl;
  };

} // NAMESPACE
