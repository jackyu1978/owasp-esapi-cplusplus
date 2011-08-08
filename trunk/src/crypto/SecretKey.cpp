/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 *
 */

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"

#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

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

  bool operator==(const SecretKey& lhs, const SecretKey& rhs) { return lhs.secBlock == rhs.secBlock; }
  bool operator!=(const SecretKey& lhs, const SecretKey& rhs)  { return lhs.secBlock != rhs.secBlock; }
    
  std::ostream& operator<<(std::ostream& os, const SecretKey& rhs)
  {
    // Using an insecure 'hex' string (it does not zeroize). We could switch to a
    // SecByteBlock and ArraySink, but the std::ostream would still be insecure.
    std::string hex;
    CryptoPP::ArraySource(rhs.BytePtr(), rhs.SizeInBytes(), true, /* don't buffer */
      new CryptoPP::HexEncoder( new CryptoPP::StringSink(hex) )
    );

    return (os << hex);
  }

}; // NAMESPACE espai
