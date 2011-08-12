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
*
*/

/////////////////////////////////////////////////////////////
// Used by Windows. For Linux, Boost::Test provides main() //
/////////////////////////////////////////////////////////////

#include "crypto/KeyDerivationFunction.h"
using esapi::KeyDerivationFunction;

#include "crypto/SecretKey.h"
using esapi::SecretKey;
using esapi::Key;

#include "crypto/KeyGenerator.h"
using esapi::KeyGenerator;

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

int main(int, char**)
{
  /*
  string password = "password";
  string salt = "salt";
  SecretKey k = KeyDerivationFunction::computeDerivedKey(20*8, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), 2);
  cout << "Ours: " << k << endl;
  */

  KeyGenerator* kg = KeyGenerator::getInstance("Sha1");
  kg->init(16 * 8);
  kg->init(16*8);
  SecretKey kk = kg->generateKey();
  Key& kr = kk;

  return 0;
}
