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

#include "errors/EncryptionException.h"
using esapi::EncryptionException;

#include "errors/InvalidArgumentException.h"
using esapi::InvalidArgumentException;

#include "crypto/SecureRandom.h"
using esapi::SecureRandom;

#include "crypto/RandomPool.h"
using esapi::RandomPool;

#include "crypto/KeyGenerator.h"
using esapi::KeyGenerator;

#include "crypto/SecretKey.h"
using esapi::SecretKey;

#include <iostream>
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
  byte scratch[32];

  RandomPool& pool = RandomPool::GetSharedInstance();
  pool.GenerateBlock(scratch, sizeof(scratch));

  pool.Reseed();
  pool.GenerateBlock(scratch, sizeof(scratch));

#if 0 
  SecureRandom prng = SecureRandom::getInstance("SHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));
#endif

  prng = SecureRandom::getInstance("HmacSHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));


#if 0 
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

  return 0;
}
