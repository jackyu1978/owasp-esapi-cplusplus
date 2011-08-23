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

#if 0 
  RandomPool& pool = RandomPool::GetSharedInstance();
  pool.GenerateBlock(scratch, sizeof(scratch));

  pool.Reseed();
  pool.GenerateBlock(scratch, sizeof(scratch));
#endif

  SecureRandom prng = SecureRandom::getInstance("SHA1");
  prng.nextBytes(scratch, sizeof(scratch));
  prng.setSeed(scratch, sizeof(scratch));

  return 0;
}
