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

#include "crypto/RandomPool.h"
#include "util/ArrayZeroizer.h"
#include "errors/EncryptionException.h"
#include "errors/InvalidArgumentException.h"

namespace esapi
{
  bool RandomPool::GenerateKey(byte* key, size_t ksize)
  {
    ASSERT(key && ksize);
    if(!key || !ksize) return false;

    return false;
  }

  bool RandomPool::GetTimeData(byte* data, size_t dsize)
  {
    ASSERT(data && dsize);
    if(!data || !dsize) return false;

    return false;
  }
}
