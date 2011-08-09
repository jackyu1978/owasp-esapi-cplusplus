/*
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
 */

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"
#include "crypto/SecureRandom.h"

#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

namespace esapi
{
  SecretKey::SecretKey(const std::string& alg,
                       const size_t size,
                       const std::string& format)
    : m_algorithm(alg), secBlock(size), m_format(format)
  {
    ASSERT( !m_algorithm.empty() );
    ASSERT( secBlock.size() );
    ASSERT( !m_format.empty() );

    if(size)
      {
        SecureRandom& prng = SecureRandom::GlobalSecureRandom();
        prng.nextBytes(secBlock.BytePtr(), secBlock.SizeInBytes());
      }
  }

  SecretKey::SecretKey(const std::string& alg,
                       const CryptoPP::SecByteBlock& bytes,
                       const std::string& format)
    : m_algorithm(alg), secBlock(bytes), m_format(format)
  {
    ASSERT( !m_algorithm.empty() );
    ASSERT( secBlock.size() );
    ASSERT( !m_format.empty() );
  }

  SecretKey::~SecretKey()
  {
  }

  SecretKey::SecretKey(const SecretKey& rhs)
    : secBlock(rhs.secBlock)
  {
  }

  SecretKey& SecretKey::operator=(const SecretKey& rhs)
  {
    // No self assignment
    if(this != &rhs)
      {
        secBlock = rhs.secBlock;
      }

    return *this;
  }

  size_t SecretKey::sizeInBytes() const
  {
    return secBlock.SizeInBytes();
  }

  const byte* SecretKey::getEncoded() const
  {
    return BytePtr();
  }

  std::string SecretKey::getFormat() const
  {
    return m_format;
  }

  std::string SecretKey::getAlgorithm() const
  {
    return m_algorithm;
  }

  /***********************    not so sure about this one...
  byte* SecretKey::BytePtr()
  {
    return secBlock.BytePtr();
  }
  *********************************************************/

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
    CryptoPP::ArraySource(rhs.BytePtr(), rhs.sizeInBytes(), true, /* don't buffer */
                          new CryptoPP::HexEncoder( new CryptoPP::StringSink(hex) )
                          );

    return (os << hex);
  }

}; // NAMESPACE espai
