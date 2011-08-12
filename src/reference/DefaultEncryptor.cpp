/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "reference/DefaultEncryptor.h"

#include <string>

namespace esapi
{
  std::string DefaultEncryptor::hashAlgorithm = "SHA-512";
  unsigned int DefaultEncryptor::hashIterations = 1024;
}