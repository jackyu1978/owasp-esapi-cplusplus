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
#include "AccessReferenceMap.h"

namespace esapi
{
  class ESAPI_EXPORT IntegerAccessReferenceMap : AccessReferenceMap
    {
    protected:

      virtual String getUniqueReference() =0;

    private:
      int count;

      virtual ~IntegerAccessReferenceMap() {};
    };
};

