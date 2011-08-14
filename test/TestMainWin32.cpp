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

#include "crypto/KeyDerivationFunction.h"
using esapi::KeyDerivationFunction;

#include "crypto/SecretKey.h"
using esapi::SecretKey;
using esapi::Key;

#include "crypto/KeyGenerator.h"
using esapi::KeyGenerator;

#include "crypto/SecureRandom.h"
using esapi::SecureRandom;

#include "crypto/MessageDigest.h"
using esapi::MessageDigest;

#include "reference/DefaultEncryptor.h"
using esapi::DefaultEncryptor;

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

// auto_ptr is deprecated in C++0X
#if defined(ESAPI_CPLUSPLUS_UNIQUE_PTR)
  using std::unique_ptr;
# define THE_AUTO_PTR  unique_ptr
#else
  using std::auto_ptr;
# define THE_AUTO_PTR  std::auto_ptr
#endif

int main(int, char**)
{
  /*
  string password = "password";
  string salt = "salt";
  SecretKey k = KeyDerivationFunction::computeDerivedKey(20*8, (byte*)password.data(), password.size(), (byte*)salt.data(), salt.size(), 2);
  cout << "Ours: " << k << endl;
  */

  //byte p[8], s[8];
  //SecureRandom prng;

  //prng.nextBytes(p, sizeof(p));
  //prng.nextBytes(s, sizeof(s));
  // string password((char*)p, sizeof(p)), salt((char*)s, sizeof(s));

  string password="", salt = "salt";
  string encoded;
  try
  {
    DefaultEncryptor encryptor;
    encoded = encryptor.hash(password, salt);
  }
  catch(InvalidArgumentException&)
  {
  }
  catch(EncryptionException&)
  {
  }
  catch(...)
  {
  }

  cout << DefaultEncryptor::DefaultDigestAlgorithm << ", " << encoded << endl;

  return 0;
}
