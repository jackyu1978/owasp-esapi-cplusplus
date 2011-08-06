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
#include "crypto/KeyGenerator.h"

#include <cstddef>
#include <stdexcept>

/**
 * This class implements functionality similar to Java's KeyGenerator for consistency
 */
namespace esapi
{
  const std::string KeyGenerator::DefaultAlgorithm = "AES/CFB";
  const unsigned int KeyGenerator::DefaultKeySize = 128;

  KeyGenerator* KeyGenerator::getInstance(const std::string& agorithm)
  {
    return nullptr;
  }
   
} // NAMESPACE esapi
