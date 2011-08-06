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
 */

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"

namespace esapi
{
  SecretKey::SecretKey(size_t size)
    : secBlock(size)
  {
  }

  SecretKey::~SecretKey()
  {
  }

  SecretKey::SecretKey(const SecretKey& lhs)
    : secBlock(lhs.secBlock)
  {
  }

  SecretKey& SecretKey::operator=(const SecretKey& lhs)
  {
    // No self assignment
    if(this != &lhs)
      {
        secBlock = lhs.secBlock;
      }

    return *this;
  }

  size_t SecretKey::SizeInBytes() const
  {
    return secBlock.SizeInBytes();
  }

  byte* SecretKey::BytePtr()
  {
    return secBlock.BytePtr();
  }

  const byte* SecretKey::BytePtr() const
  {
    return secBlock.BytePtr();
  }

}; // NAMESPACE espai
