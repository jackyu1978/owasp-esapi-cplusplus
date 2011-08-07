/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author kevin.w.wall@gmail.com
 * @author noloader@gmail.com
 *
 */

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"

#include <string>

#ifndef __INCLUDED_KEY_ENCRYPTOR__
#define __INCLUDED_KEY_ENCRYPTOR__

#pragma once

namespace esapi
{
  class KeyGenerator
  {
    public:
      static const std::string DefaultAlgorithm;
      static const unsigned int DefaultKeySize;

    public:
      static KeyGenerator* getInstance(const std::string& algorithm = DefaultAlgorithm);

      virtual void init(unsigned int keyBits = DefaultKeySize) = 0;

      virtual SecretKey generateKey() = 0;

      virtual std::string algorithm() const = 0;

    protected:
      // This class calls CreateInstance on a derived class
      static KeyGenerator* CreateInstance();

    protected:
      // Not for general consumption
      KeyGenerator(const std::string& algorithm = "")
        : m_algorithm(algorithm) { /* No external instantiations */ }

    protected:
      unsigned int m_keyBits;
      std::string m_algorithm;
  };

  ////////////////////////// Block Ciphers //////////////////////////

  template <class CIPHER, template <class CIPHER> class MODE>
  class BlockCipherGenerator : public KeyGenerator
  {
    typedef typename MODE < CIPHER >::Encryption ENCRYPTOR;

    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      static KeyGenerator* getInstance(const std::string& algorithm);

      virtual void init(unsigned int keyBits);

      virtual SecretKey generateKey();

      // Return the algorithm name (eg, AES/CFB)
      virtual std::string algorithm() const;

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. m_cipher does not cough up its name
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
      static KeyGenerator* getInstance(const std::string& algorithm);

      virtual void init(unsigned int keyBits);

      virtual SecretKey generateKey();

      // Return the algorithm name (eg, SHA-1)
      virtual std::string algorithm() const;

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. The hash does not cough up its name
      HashGenerator(const std::string& algorithm);

  }; // HashGenerator

  ////////////////////////// HMACs //////////////////////////

  template <class HM>
  class HmacGenerator : public KeyGenerator
  {
    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      static KeyGenerator* getInstance(const std::string& algorithm);

      virtual void init(unsigned int keyBits);

      virtual SecretKey generateKey();

      // Return the algorithm name (eg, SHA-1)
      virtual std::string algorithm() const;

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. The hash does not cough up its name
      HmacGenerator(const std::string& algorithm);

  }; // HmacGenerator

  ////////////////////////// Stream Ciphers ////////////////////////

  template <class SS>
  class StreamCipherGenerator : public KeyGenerator
  {
    // Base class needs access to protected CreateInstance in derived class
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      static KeyGenerator* getInstance(const std::string& algorithm);

      virtual void init(unsigned int keyBits);

      virtual SecretKey generateKey();

      // Return the algorithm name (eg, SHA-1)
      virtual std::string algorithm() const;

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. The hash does not cough up its name
      StreamCipherGenerator(const std::string& algorithm);

  }; // StreamCipherGenerator

}; // NAMESPACE esapi

#endif // __INCLUDED_KEY_ENCRYPTOR__
