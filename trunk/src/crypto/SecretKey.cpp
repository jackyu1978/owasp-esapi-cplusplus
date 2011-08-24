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

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"
#include "crypto/SecureRandom.h"
#include "crypto/Crypto++Common.h"

namespace esapi
{
  SecretKey::SecretKey(const std::string& alg,
    const size_t sizeInBytes,
    const std::string& format)
    : m_algorithm(alg), secBlock(sizeInBytes), m_format(format)
  {
    ASSERT( !m_algorithm.empty() );
    ASSERT( secBlock.size() );
    ASSERT( !m_format.empty() );

    if(sizeInBytes)
    {
      SecureRandom prng = SecureRandom::getInstance(alg);
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
    : Key(rhs), m_algorithm(rhs.m_algorithm), secBlock(rhs.secBlock), m_format(rhs.m_format)
  {
  }

  SecretKey& SecretKey::operator=(const SecretKey& rhs)
  {
    // No self assignment
    if(this != &rhs)
    {
      Key::operator =(rhs);

      m_algorithm = rhs.m_algorithm;
      secBlock = rhs.secBlock;
      m_format = rhs.m_format;
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

  // The return value is a bit confusing. If the key supports encoding, return
  // the ASN.1 name for the method, otherwise retun the empty string. If the
  // key does *not* support encoding, return "RAW".
  std::string SecretKey::getFormat() const
  {
    ASSERT( !m_format.empty() );

    return m_format;
  }

  std::string SecretKey::getAlgorithm() const
  {
    return m_algorithm;
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
    CryptoPP::ArraySource(rhs.BytePtr(), rhs.sizeInBytes(), true, /* don't buffer */
      new CryptoPP::HexEncoder( new CryptoPP::StringSink(hex) )
      );

    return (os << hex);
  }

}; // NAMESPACE espai
