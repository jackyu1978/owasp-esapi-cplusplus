/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#pragma once

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "util/SecureArray.h"
#include "crypto/RandomPool.h"
#include "crypto/Crypto++Common.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"
#include "errors/UnsupportedOperationException.h"

#include <string>
#include <vector>
#include <stdexcept>
#include <cassert>

#include <boost/shared_ptr.hpp>

namespace esapi
{
  /**
   * This class implements functionality similar to Java's SecureRandom for consistency
   * http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html
   */

  class SecureRandomImpl;

  ///////////////////////////////////////////////////////////////////////////////////
  ////////////////////////////////// Secure Random //////////////////////////////////
  ///////////////////////////////////////////////////////////////////////////////////

  class ESAPI_EXPORT SecureRandom
  {
    // KeyGenerator needs access to getSecurityLevel()
    friend class KeyGenerator;

    // While it make sense to make DefaultAlgorithm a public static string, we can't
    // be sure of initializtion order of non-local statics. So it becomes a function.

  public:
    /**
     * The default secure random number generator (RNG) algorithm. Currently returns
     * SHA-256. SHA-1 is approved for Random Number Generation. See SP 800-57, Table 2.
     */
    static String DefaultAlgorithm();

    /**
     * Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
     */
    static SecureRandom getInstance(const String& algorithm = DefaultAlgorithm());

    /**
     * Constructs a secure random number generator (RNG) implementing the named
     * random number algorithm if specified
     */
    explicit SecureRandom(const String& algorithm = DefaultAlgorithm());

    /**
     * Constructs a secure random number generator (RNG) implementing the default random number algorithm.
     */
    explicit SecureRandom(const byte* seed, size_t size);

    /**
     * Destroy this random number generator (RNG).
     */
    ~SecureRandom() { };

    /**
     * Copy this secure random number generator (RNG).
     */
    SecureRandom(const SecureRandom& rhs);

    /**
     * Assign this secure random number generator (RNG).
     */
    SecureRandom& operator=(const SecureRandom& rhs);

    /**
     * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
     */
    SecureByteArray generateSeed(unsigned int numBytes);

    /**
     * Returns the name of the algorithm implemented by this SecureRandom object.
     */
    String getAlgorithm() const;

    /**
     * Generates a user-specified number of random bytes.
     */
    void nextBytes(byte* bytes, size_t size);

    /**
     * Reseeds this random object.
     */
    void setSeed(const byte seed[], size_t size);

    /**
     * Reseeds this random object, using the bytes contained in the given long seed.
     */
    void setSeed(int seed);

  protected:

    /**
     * Constructs a secure random number generator (RNG) from a SecureRandomImpl implementation.
     */
    ESAPI_PRIVATE SecureRandom(SecureRandomImpl* impl);

    /**
     * Returns the security level associated with the SecureRandom object. Used
     * by KeyGenerator to determine the appropriate key size for init.
     */
    ESAPI_PRIVATE unsigned int getSecurityLevel() const;

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
    boost::shared_ptr<SecureRandomImpl> m_impl;
  };  

}; // NAMESPACE esapi
