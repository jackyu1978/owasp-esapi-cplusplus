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

#ifndef __INCLUDED_KEY_GENERATOR__
#define __INCLUDED_KEY_GENERATOR__

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

      virtual void init(unsigned int keySize = DefaultKeySize) = 0;

      virtual SecretKey generateKey() = 0;

      virtual std::string algorithm() const = 0;

    protected:
      // This class calls CreateInstance on a derived class
      static KeyGenerator* CreateInstance();

    protected:
      // Not for general consumption
      KeyGenerator() { /* No public instantiations */ }

    protected:
      unsigned int m_keySize;
	  std::string m_algorithm;
  };

  template <class CIPHER, template <class CIPHER> class MODE>
  class BlockCipherGenerator : public KeyGenerator
  {
    // Base class needs access to protected CreateInstance
    friend KeyGenerator* KeyGenerator::getInstance(const std::string&);

    public:
      static KeyGenerator* getInstance(const std::string& algorithm);

      virtual void init(unsigned int keySize);

      virtual SecretKey generateKey();

      // Return the algorithm name (eg, AES/CFB)
      virtual std::string algorithm() const;

    protected:
      // Called by base class KeyGenerator::getInstance
      static KeyGenerator* CreateInstance(const std::string& algorithm);

      // Sad, but true. m_cipher does not cough up its name
      BlockCipherGenerator(const std::string& algorithm);

    private:
        MODE < CIPHER > m_cipher;
  };
}; // NAMESPACE esapi

#endif // __INCLUDED_KEY_GENERATOR__
