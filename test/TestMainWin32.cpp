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

#include "errors/IllegalArgumentException.h"
using esapi::IllegalArgumentException;

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

#include "util/TextConvert.h"
using esapi::TextConvert;

#include "util/AlgorithmName.h"
using esapi::AlgorithmName;

#include "crypto/Cipher.h"
using esapi::Cipher;

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
#if 0
  try
  {
    KeyGenerator kgen = KeyGenerator::getInstance("AES");
    kgen.init(128);
    SecretKey key = kgen.generateKey();

    Cipher c = Cipher::getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher::ENCRYPT_MODE, key);
  }
  catch(const std::exception& ex)
  {
    cerr << ex.what() << endl;
  }

  try
  {
    KeyGenerator kgen = KeyGenerator::getInstance("SHA-256");
    kgen.init(128);
    SecretKey key = kgen.generateKey();

    Cipher c = Cipher::getInstance("AES/ECB/PKCS5Padding");
    c.init(Cipher::ENCRYPT_MODE, key);
  }
  catch(const std::exception& ex)
  {
    cerr << ex.what() << endl;
  }

  try
  {
    KeyGenerator kgen = KeyGenerator::getInstance("SHA-256");
    kgen.init(128);
    SecretKey key = kgen.generateKey();

    Cipher c = Cipher::getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher::ENCRYPT_MODE, key);
  }
  catch(const std::exception& ex)
  {
    cerr << ex.what() << endl;
  }
#endif
  return 0;
}
