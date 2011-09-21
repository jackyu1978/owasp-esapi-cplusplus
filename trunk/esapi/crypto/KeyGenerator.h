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
#include "crypto/SecretKey.h"
#include "crypto/SecureRandom.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

#include <string>

namespace esapi
{
  /**
  * This class implements functionality similar to Java's KeyGenerator for consistency
  * http://download.oracle.com/javase/6/docs/api/javax/crypto/KeyGenerator.html
  */
  class ESAPI_EXPORT KeyGenerator
  {
  public:
    // While it make sense to make DefaultAlgorithm and DefaultKeySize public static objects,
    // we can't be sure of initializtion order of non-local statics. So they become functions.

    /**
    * Returns the default algorithm used for key generation.
    */
    static String DefaultAlgorithm();

    /**
    * Returns the default key size for key generation.
    */
    static unsigned int DefaultKeySize();

  public:
    /**
    * Returns a KeyGenerator object that generates secret keys for the specified algorithm.
    */
    static KeyGenerator getInstance(const String& algorithm = DefaultAlgorithm());

    /**
    * Initializes this key generator for a certain keysize.
    */
    virtual void init(unsigned int keyBits = DefaultKeySize());

    /**
    * Initializes this key generator for a certain keysize, using a user-provided source of randomness.
    */
    virtual void init(unsigned int keyBits, const SecureRandom& random);
          
    /**
    * Initializes this key generator.
    */
    virtual void init(const SecureRandom& random);

    /**
    * Returns the algorithm name of this KeyGenerator object.
    */
    virtual String getAlgorithm() const;

    /**
    * Generates a secret key.
    */
    virtual SecretKey generateKey();

    /**
    * Destroys a KeyGenerator object.
    */
    virtual ~KeyGenerator() { }

    /**
    * Copy a KeyGenerator object (SecureRandom is safe to copy).
    */
    KeyGenerator(const KeyGenerator& rhs);

    /**
    * Assign a KeyGenerator object (SecureRandom is safe to copy).
    */
    KeyGenerator& operator=(const KeyGenerator& rhs);

  protected:

    // Initialize m_keyBytes to an invalid size
    enum { InvalidKeyBytes = -1 };

  protected:
    /**
    * Creates a KeyGenerator object.
    */
    ESAPI_PRIVATE explicit KeyGenerator(const String& algorithmName = DefaultAlgorithm());

  private:
    /**
    * A java like reference to a SecureRandom object, which will generate the bit stream.
    */
    SecureRandom m_random;

    /**
    * Size of the key to generate, in bits.
    */
    unsigned int m_keyBytes;
  };
}; // NAMESPACE esapi
