/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* @author Kevin Wall, kevin.w.wall@gmail.com
* @author Jeffrey Walton, noloader@gmail.com
*/

#pragma once

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "util/SecureArray.h"



namespace esapi
{
  class Key;
  class CipherImpl;
  class SecureRandom;
  class AlgorithmParameters;

  class ESAPI_EXPORT Cipher
  {
  public:

    enum CipherMode { DecryptMode = 1, EncryptMode, WrapMode, UnwrapMode };
    static const size_t DECRYPT_MODE = Cipher::DecryptMode;
    static const size_t ENCRYPT_MODE = Cipher::EncryptMode;
    static const size_t WRAP_MODE = Cipher::WrapMode;
    static const size_t UNWRAP_MODE = Cipher::UnwrapMode;

    enum CipherKey { PrivateKey = 1, PublicKey, SecretKey };
    static const size_t PRIVATE_KEY = Cipher::PublicKey;
    static const size_t PUBLIC_KEY = Cipher::PrivateKey;
    static const size_t SECRET_KEY = Cipher::SecretKey;

  public:

    /**
    * Generates a Cipher object that implements the specified transformation.
    */
    static Cipher getInstance(const String& algorithm);

    /**
    * Generates a Cipher object that implements the specified transformation.
    */
    static Cipher getInstance(const NarrowString& algorithm);

    /**
    * Copies a cipher.
    */
    Cipher(const Cipher& cipher);

    /**
    * Destroys a cipher.
    */
    virtual ~Cipher() { };

    /**
    * Assigns a cipher.
    */
    Cipher& operator=(const Cipher& cipher);

    /**
    * Finishes a multiple-part encryption or decryption operation,
    * depending on how this cipher was initialized.
    */
    SecureByteArray doFinal();

    /**
    * Encrypts or decrypts data in a single-part operation, or finishes
    * a multiple-part operation.
    */
    SecureByteArray doFinal(const byte input[], size_t size);

    /**
    * Encrypts or decrypts data in a single-part operation, or finishes
    * a multiple-part operation.
    */
    SecureByteArray doFinal(const SecureByteArray& input);

    /**
    * Finishes a multiple-part encryption or decryption operation,
    * depending on how this cipher was initialized.
    */
    size_t doFinal(const byte output[], size_t size, size_t outputOffset);

    /**
    * Finishes a multiple-part encryption or decryption operation,
    * depending on how this cipher was initialized.
    */
    size_t doFinal(SecureByteArray& output, size_t outputOffset);

    /**
    * Encrypts or decrypts data in a single-part operation, or finishes
    * a multiple-part operation.
    */
    SecureByteArray doFinal(const byte input[], size_t size, size_t inputOffset, size_t inputLen);

    /**
    * Encrypts or decrypts data in a single-part operation, or finishes
    * a multiple-part operation.
    */
    SecureByteArray doFinal(const SecureByteArray& input, size_t inputOffset, size_t inputLen);

    /**
    * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
    */
    size_t doFinal(const byte input[], size_t inSize, size_t inputOffset, size_t inputLen, byte output[], size_t outSize);

    /**
    * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
    */
    size_t doFinal(const SecureByteArray& input, size_t inputOffset, size_t inputLen, SecureByteArray& output);

    /**
    * Returns the algorithm name of this Cipher object.
    */
    String getAlgorithm() const;

    /**
    * Returns the initialization vector (IV) in a new buffer.
    */
    SecureByteArray getIV() const;

    /**
    * Returns the length in bytes that an output buffer would need to be in order to hold the result
    * of the next update or doFinal operation, given the input length inputLen (in bytes).
    */
    size_t getOutputSize(size_t inputLen) const;

    /**
    * Initializes this cipher with a key.
    */
    void init(size_t opmode, const Key& key);

    /**
    * Initializes this cipher with a key, a set of algorithm parameters, and a source of randomness.
    */
    void init(int opmode, const Key& key, AlgorithmParameters& params, SecureRandom& random);

    /**
    * Initializes this cipher with a key and a source of randomness.
    */
    void init(int opmode, const Key& key, SecureRandom& random);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    SecureByteArray update(const byte input[], size_t size);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    SecureByteArray update(const SecureByteArray& input);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    SecureByteArray update(const byte input[], size_t size, size_t inputOffset, size_t inputLen);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    SecureByteArray update(const SecureByteArray& input, size_t inputOffset, size_t inputLen);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    size_t update(const byte input[], size_t inSize, size_t inputOffset, size_t inputLen, byte output[], size_t outSize);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    size_t update(const SecureByteArray& input, size_t inputOffset, size_t inputLen, SecureByteArray& output);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    size_t update(const byte input[], size_t inSize, size_t inputOffset, size_t inputLen, byte output[], size_t outSize, size_t outputOffset);

    /**
    * Continues a multiple-part encryption or decryption operation (depending on how this cipher
    * was initialized), processing another data part.
    */
    size_t update(const SecureByteArray& input, size_t inputOffset, size_t inputLen, SecureByteArray& output, size_t outputOffset);

#if 0
    /**
    * Unwrap a previously wrapped key. 
    */
    Key unwrap(const byte wrappedKey[], const String& wrappedKeyAlgorithm, int wrappedKeyType);

    /**
    * Unwrap a previously wrapped key. 
    */
    Key unwrap(const SecureByteArray& wrappedKey, const String& wrappedKeyAlgorithm, int wrappedKeyType);

    /**
    * Wrap a key. 
    */
    SecureByteArray wrap(const Key& key);           
#endif

  protected:

    /**
    * Creates a cipher with the specified algorithm name.
    */
    explicit Cipher(const String& algorithm);

    /**
    * Creates a Cipher from an implmentation. Used by getInstance(...).
    */
    ESAPI_PRIVATE Cipher(CipherImpl* impl);

    /**
    * Retrieves the object level lock
    */
    ESAPI_PRIVATE inline Mutex& getObjectLock() const;

  private:

    /**
    * Object level lock for concurrent access
    */
    mutable shared_ptr<Mutex> m_lock;

    /**
    * Reference counted PIMPL.
    */
    shared_ptr< CipherImpl > m_impl;
  };

} // NAMESPACE

