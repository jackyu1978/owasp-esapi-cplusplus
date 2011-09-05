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

/////////////////////////////////////////////////////////////
// Used by Windows. For Linux, Boost::Test provides main() //
/////////////////////////////////////////////////////////////

#include "EsapiCommon.h"

#include "errors/InvalidArgumentException.h"
using esapi::InvalidArgumentException;

#include "errors/EncryptionException.h"
using esapi::EncryptionException;

#include "errors/NoSuchAlgorithmException.h"
using esapi::NoSuchAlgorithmException;

#include "crypto/SecureRandom.h"
using esapi::SecureRandom;

#include "crypto/RandomPool.h"
using esapi::RandomPool;

#include "crypto/KeyGenerator.h"
using esapi::KeyGenerator;

#include "crypto/SecretKey.h"
using esapi::SecretKey;

#include "crypto/MessageDigest.h"
using esapi::MessageDigest;

#include "util/SecureArray.h"
using esapi::SecureByteArray;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstddef>
#include <memory>
#include <string>
using std::string;

int main(int, char**)
{
#if 0
  byte scratch[32];

  RandomPool& pool = RandomPool::GetSharedInstance();
  pool.GenerateBlock(scratch, sizeof(scratch));

  pool.Reseed();
  pool.GenerateBlock(scratch, sizeof(scratch));

  SecureRandom prng = SecureRandom::getInstance("SHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));

  prng = SecureRandom::getInstance("HmacSHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));

  KeyGenerator kg = KeyGenerator::getInstance("SHA-384");
  kg.init();

  cout << "Generator: " << kg.getAlgorithm() << endl;

  SecretKey key = kg.generateKey();
  cout << "Key: " << key.getAlgorithm() << endl;
  cout << "Key size: " << key.sizeInBytes() << endl;

  kg = KeyGenerator::getInstance("SHA-512");
  kg.init(384);

  cout << "Generator: " << kg.getAlgorithm() << endl;

  key = kg.generateKey();
  cout << "Key: " << key.getAlgorithm() << endl;
  cout << "Key size: " << key.sizeInBytes() << endl;
#endif

  try
    {
      //MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
      bool success = false;
      MessageDigest md(MessageDigest::getInstance("MD5"));

      const size_t sz = md.getDigestLength();
      SecureByteArray buf(sz);

      const string msg("");
      md.update((const byte*)msg.data(), msg.size());

      const byte hash[16] = {0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e};
      md.digest(buf.data(), buf.size(), 0, sz);
      success = (::memcmp(buf.data(), hash, 16) == 0);
      ASSERT(success);

      /* ======================= */

      MessageDigest zzz;
      MessageDigest xxx(md);
      MessageDigest yyy = xxx;

      /* ======================= */

      MessageDigest md5 = MessageDigest::getInstance("MD5");
      md5.update((const byte*)msg.data(), msg.size());

      SecureByteArray digest = md5.digest();
      ASSERT(digest.size() == COUNTOF(hash));

      success = (::memcmp(digest.data(), hash, 16) == 0);
      ASSERT(success);

    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }

  return 0;
}
