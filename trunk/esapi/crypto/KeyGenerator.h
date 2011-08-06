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

#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>

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
      KeyGenerator* getInstance(const std::string& agorithm = DefaultAlgorithm);

      virtual void init(unsigned int keySize = DefaultKeySize) = 0;

      virtual SecretKey generateKey() = 0;

	private:
      KeyGenerator() { /* No instantiations */ }
  };

}; // NAMESPACE esapi

#endif // __INCLUDED_KEY_GENERATOR__
