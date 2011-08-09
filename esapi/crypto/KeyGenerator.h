/*
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

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"

#include <string>

#ifndef __INCLUDED_KEY_GENERATOR__
#define __INCLUDED_KEY_GENERATOR__

#pragma once

namespace esapi
{
  /**
   * This class implements functionality similar to Java's KeyGenerator for consistency
   * http://download.oracle.com/javase/6/docs/api/javax/crypto/KeyGenerator.html
   */
  class KeyGenerator
  {
    public:
      static const std::string DefaultAlgorithm;
      static const unsigned int DefaultKeySize;

    public:
      static KeyGenerator* getInstance(const std::string& algorithm = DefaultAlgorithm);

      // Initialize the generator for use.
      virtual void init(unsigned int keyBits = DefaultKeySize);

      // Return the standard algorithm name.
      virtual std::string getAlgorithm() const;

      // Generate a SecretKey. Must be overriden in derived classes.
      virtual SecretKey generateKey() = 0;

    protected:
      // This class calls CreateInstance on a derived class
      static KeyGenerator* CreateInstance();

      // Called by derived classes in init()
      void SetKeySize(unsigned int keySize);

      // Called by derived classes to fetch key bytes (not bits)
      unsigned int GetKeySize() const;

      // Called by derived classes in CreateInstance()
      void SetAlgorithmName(const std::string& algorithmName);

      // Single testing point to ensure init() has been called. All derived
      // classes *must* call VerifyKeyBitsSize() in their generateKey().
      void VerifyKeyBitsSize() const;

    protected:
      // Not for general consumption
      KeyGenerator(const std::string& algorithmName = "") : m_algorithm(algorithmName),
        m_keyBits(NoKeySize) { /* No external instantiations */ }    

    protected:
      static const unsigned int NoKeySize;
      static const unsigned int MaxKeySize;

    private:
      std::string m_algorithm;
      unsigned int m_keyBits;  
  };

  ////////////////////////// Block Ciphers //////////////////////////

  template <class CIPHER, template <class CIPHER> class MODE>
  class BlockCipherGenerator : public KeyGenerator
  {
    typedef typename MODE < CIPHER >::Encryption ENCRYPTOR;

    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      // Initialize the generator for use. Block ciphers set the key
      // in init(), and change the initialization vector in generateKey()
      virtual void init(unsigned int keyBits);

      // Generate a SecretKey.
      virtual SecretKey generateKey();

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. ENCRYPTOR does not always cough up its name
      BlockCipherGenerator(const std::string& algorithm);

    private:
      ENCRYPTOR m_encryptor;

  }; // BlockCipherGenerator

  ////////////////////////// Hashes //////////////////////////

  template <class HASH>
  class HashGenerator : public KeyGenerator
  {
    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      // Initialize the generator for use. Base class processing is
      // fine for HashGenerator
      // virtual void init(unsigned int keyBits);

      // Generate a SecretKey.
      virtual SecretKey generateKey();

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. The hash does not always cough up its name
      HashGenerator(const std::string& algorithm);

  }; // HashGenerator

  ////////////////////////// HASHs //////////////////////////

  template <class HASH>
  class HmacGenerator : public KeyGenerator
  {
    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      // Initialize the generator for use. Base class processing is
      // fine for HmacGenerator
      // virtual void init(unsigned int keyBits);

      // Generate a SecretKey.
      virtual SecretKey generateKey();

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. The hash does not always cough up its name
      HmacGenerator(const std::string& algorithm);

  }; // HmacGenerator

  ////////////////////////// Stream Ciphers ////////////////////////

  template <class CIPHER>
  class StreamCipherGenerator : public KeyGenerator
  {
    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      // Initialize the generator for use. Base class processing is
      // fine for StreamCipherGenerator
      // virtual void init(unsigned int keyBits);

      // Generate a SecretKey.
      virtual SecretKey generateKey();

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. The stream cipher does not always cough up its name
      StreamCipherGenerator(const std::string& algorithm);

  }; // StreamCipherGenerator

}; // NAMESPACE esapi

#endif // __INCLUDED_KEY_GENERATOR__

