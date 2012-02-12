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
  SecretKey::SecretKey(const NarrowString& alg,
    const size_t sizeInBytes,
    const NarrowString& format)
    : m_algorithm(alg), m_secBlock(sizeInBytes), m_format(format)
  {
    ASSERT( !m_algorithm.empty() );
    ASSERT( m_secBlock.size() );
    ASSERT( !m_format.empty() );

    if(sizeInBytes)
    {
      SecureRandom prng = SecureRandom::getInstance(alg);
      prng.nextBytes(m_secBlock.data(), m_secBlock.size());
    }
  }

  SecretKey::SecretKey(const NarrowString& alg,
    const CryptoPP::SecByteBlock& bytes,
    const NarrowString& format)
    : m_algorithm(alg), m_secBlock(bytes), m_format(format)
  {
    ASSERT( !m_algorithm.empty() );
    ASSERT( m_secBlock.size() );
    ASSERT( !m_format.empty() );
  }

  SecretKey::SecretKey(const NarrowString& alg,
    const SecureByteArray& bytes,
    const NarrowString& format)
    : m_algorithm(alg), m_secBlock(bytes.data(), bytes.size()), m_format(format)
  {
    ASSERT( !m_algorithm.empty() );
    ASSERT( m_secBlock.size() );
    ASSERT( !m_format.empty() );
  }

  SecretKey::~SecretKey()
  {
  }

  SecretKey::SecretKey(const SecretKey& rhs)
    : Key(rhs), m_algorithm(rhs.m_algorithm), m_secBlock(rhs.m_secBlock), m_format(rhs.m_format)
  {
  }

  SecretKey& SecretKey::operator=(const SecretKey& rhs)
  {
    // No self assignment
    if(this != &rhs)
    {
      Key::operator =(rhs);

      m_algorithm = rhs.m_algorithm;
      m_secBlock = rhs.m_secBlock;
      m_format = rhs.m_format;
    }

    return *this;
  }

  /**
   * Assign a SecretKey
   */
  SecretKey& SecretKey::operator=(const SecureByteArray& rhs)
  {
      m_algorithm = "Unknown";
      m_secBlock = CryptoPP::SecByteBlock(rhs.data(), rhs.size());
      m_format = "RAW";

      return *this;
  }

  SecureByteArray SecretKey::getEncoded() const
  {
    ASSERT(m_secBlock.data());
    ASSERT(m_secBlock.size());
    return SecureByteArray(m_secBlock.data(), m_secBlock.size());
  }

  // The return value is a bit confusing. If the key supports encoding, return
  // the ASN.1 name for the method, otherwise retun the empty string. If the
  // key does *not* support encoding, return L"RAW".
  NarrowString SecretKey::getFormat() const
  {
    ASSERT( !m_format.empty() );
    return m_format;
  }

  NarrowString SecretKey::getAlgorithm() const
  {
    ASSERT( !m_algorithm.empty() );
    return m_algorithm;
  }

  const byte* SecretKey::BytePtr() const
  {
      ASSERT(m_secBlock.data());
      return m_secBlock.data();
  }

  size_t SecretKey::sizeInBytes() const
  {
    ASSERT(m_secBlock.size());
    return m_secBlock.size();
  }

  bool operator==(const SecretKey& lhs, const SecretKey& rhs) { return lhs.m_secBlock == rhs.m_secBlock; }
  bool operator!=(const SecretKey& lhs, const SecretKey& rhs)  { return lhs.m_secBlock != rhs.m_secBlock; }

  std::ostream& operator<<(std::ostream& os, const SecretKey& rhs)
  {
    // Using an insecure 'hex' string (it does not zeroize). We could switch to a
    // SecByteBlock and ArraySink, but the std::ostream would still be insecure.
    std::string hex;

    CryptoPP::StringSource(rhs.BytePtr(), rhs.sizeInBytes(), true, /* don't buffer */
        new CryptoPP::HexEncoder( new CryptoPP::StringSink(hex) )
    );

    return (os << hex);
  }

}; // NAMESPACE espai

