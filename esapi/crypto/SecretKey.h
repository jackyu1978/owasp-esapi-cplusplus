/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#include "EsapiCommon.h"
#include <cryptopp/secblock.h>

#ifndef __INCLUDED_SECRET_KEY__
#define __INCLUDED_SECRET_KEY__

#pragma once

/**
 * This class implements functionality similar to Java's SecretKey for consistency
 */
namespace esapi
{
  class SecretKey
  {
    friend bool operator==(const SecretKey& lhs, const SecretKey& rhs);
    friend bool operator!=(const SecretKey& lhs, const SecretKey& rhs);
    friend std::ostream& operator<<(const SecretKey& lhs, std::ostream& os);

  public:
    SecretKey(size_t size);
    virtual ~SecretKey();

  public:
    SecretKey(const SecretKey& lhs);
    SecretKey& operator=(const SecretKey& lhs);

  public:
    // Hold overs from Crypto++ SecByteBlock. Change at will.
    size_t SizeInBytes() const;
    byte* BytePtr();
    const byte* BytePtr() const;

  private:
    CryptoPP::SecByteBlock secBlock;

  };

bool operator==(const SecretKey& lhs, const SecretKey& rhs);
bool operator!=(const SecretKey& lhs, const SecretKey& rhs);

std::ostream& operator<<(std::ostream& os, const SecretKey& rhs);

}; // NAMESPACE esapi

#endif // __INCLUDED_SECRET_KEY__
