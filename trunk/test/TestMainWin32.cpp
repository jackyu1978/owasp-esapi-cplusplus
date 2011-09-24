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
using esapi::String;
using esapi::NarrowString;
using esapi::WideString;

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

#include "crypto/PlainText.h"
using esapi::PlainText;

#include "crypto/CipherText.h"
using esapi::CipherText;

#include "crypto/SecretKey.h"
using esapi::SecretKey;

#include "crypto/MessageDigest.h"
using esapi::MessageDigest;

#include "util/SecureArray.h"
using esapi::SecureByteArray;
using esapi::SecureIntArray;

#include "util/SecureString.h"
using esapi::SecureString;

#include "DummyConfiguration.h"
using esapi::DummyConfiguration;

#include "reference/DefaultEncryptor.h"
using esapi::DefaultEncryptor;

#include <util/TextConvert.h>
using esapi::TextConvert;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstddef>
#include <memory>
#include <string>

static const WideString wide = L"\u9aa8";
static const NarrowString narrow("\xe9\xaa\xa8");

int main(int, char**)
{
  // String data
  String password = L"password", salt = L"salt", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"KYiahqQx3B2tJ8B8E+6FUqbD3K6UBwVoUrH6SnliOwXEe4GVHMn0pPtBiApZAmwdj7J926DUL4sk5UrE6u8bIw==";
      success = (encoded == expected);

    }
  catch(InvalidArgumentException&)
    {
      //BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      //BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      //BOOST_ERROR("Caught unknown exception");
    }

  //BOOST_CHECK_MESSAGE(success, "Failed to arrive at expected hash (calculated): " << TextConvert::WideToNarrow(encoded));

#if 0
  // String data
  String password = L"", salt = L"salt", encoded;
  bool success = false;

  try
    {
      DefaultEncryptor encryptor;
      encoded = encryptor.hash(password, salt);

      const String expected = L"v+HgWZYnwBxngZGeHgbzMzym0ROd5mRPTIrpdmeTlMoApHj/gCwUfajLWMqZHUoKDgzhgb5gSiECLzDUU9Gacg==";
      success = (encoded == expected);
    }
  catch(InvalidArgumentException&)
    {
      //BOOST_ERROR("Caught InvalidArgumentException");
    }
  catch(EncryptionException&)
    {
      //BOOST_ERROR("Caught EncryptionException");
    }
  catch(...)
    {
      //BOOST_ERROR("Caught unknown exception");
    }
#endif

#if 0
  // Han character for 'bone'
  NarrowString n1(narrow);
  WideString w1 = TextConvert::NarrowToWide(n1);

  // Han character for 'bone'
  WideString w2(wide);
  NarrowString n2 = TextConvert::WideToNarrow(w2, "UTF-8");

  // Han character for 'bone'
  WideString w3(wide);
  NarrowString n3 = TextConvert::WideToNarrow(w3, "utf-8");

  try
  {
    // Han character for 'bone'
    WideString w4(wide);
    NarrowString n4 = TextConvert::WideToNarrow(w4, "Junk");
  }
  catch(const InvalidArgumentException& ex)
  {
    cerr << ex.what() << endl;
  }

  // Han character for 'bone'
  WideString w5(wide);
  NarrowString n5 = TextConvert::WideToNarrow(w5, "65001");
#endif

#if 0
  DummyConfiguration config;
  String name = config.getApplicationName();

  DefaultEncryptor encryptor;

  PlainText plain = L"Now is the time for all good men to come to the aide of their country.";
  CipherText cipher = encryptor.encrypt(plain);
#endif

#if 0
  SecureByteArray a(10);
  SecureByteArray b(20);

  std::swap(a, b);

  cout << a.size() << ":" << b.size() << endl;

  SecureString c(L"Hello");
  SecureString d(L"Cruel World");

  std::swap(c, d);

  cout << c.size() << ":" << d.size() << endl;

  byte scratch[32];

  RandomPool& pool = RandomPool::GetSharedInstance();
  pool.GenerateBlock(scratch, sizeof(scratch));

  pool.Reseed();
  pool.GenerateBlock(scratch, sizeof(scratch));

  SecureRandom prng = SecureRandom::getInstance(L"SHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));

  prng = SecureRandom::getInstance(L"HmacSHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));

  KeyGenerator kg = KeyGenerator::getInstance(L"SHA-384");
  kg.init();

  cout << "Generator: " << kg.getAlgorithm() << endl;

  SecretKey key = kg.generateKey();
  cout << "Key: " << key.getAlgorithm() << endl;
  cout << "Key size: " << key.sizeInBytes() << endl;

  kg = KeyGenerator::getInstance(L"SHA-512");
  kg.init(384);

  cout << "Generator: " << kg.getAlgorithm() << endl;

  key = kg.generateKey();
  cout << "Key: " << key.getAlgorithm() << endl;
  cout << "Key size: " << key.sizeInBytes() << endl;

  try
  {
    //MD5 (L"") = d41d8cd98f00b204e9800998ecf8427e
    bool success = false;
    MessageDigest md(MessageDigest::getInstance(L"MD5"));

    const size_t sz = md.getDigestLength();
    SecureByteArray buf(sz);

    const string msg(L"");
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

    MessageDigest md5 = MessageDigest::getInstance(L"MD5");
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
#endif

  return 0;
}
