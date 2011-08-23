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

// gcc -g3 -ggdb -O0 -I./esapi test/TestMainWin32.cpp -o TestMain.exe -L./lib -lesapi-c++ -lstdc++ -lcryptopp

#include "errors/EncryptionException.h"
using esapi::EncryptionException;

#include "errors/InvalidArgumentException.h"
using esapi::InvalidArgumentException;

#include "crypto/RandomPool.h"
using esapi::RandomPool;

#include "crypto/SecureRandom.h"
using esapi::SecureRandom;

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

// nullptr
#include <cstddef>
#include <memory>
#include <string>
using std::string;

int main(int, char**)
{

  byte scratch[12];
  RandomPool& pool = RandomPool::GetSharedInstance();
  pool.GenerateBlock(scratch, sizeof(scratch));

  cout << (int)scratch[0] << " " << (int)scratch[1] << " " << (int)scratch[2] << " " << (int)scratch[3] << " ";
  cout << (int)scratch[4] << " " << (int)scratch[5] << " " << (int)scratch[6] << " " << (int)scratch[7] << endl;

  //prng.nextBytes(p, sizeof(p));
  //prng.nextBytes(s, sizeof(s));
  // string password((char*)p, sizeof(p)), salt((char*)s, sizeof(s));

  return 0;
}
