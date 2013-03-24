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
using esapi::StringArray;
using esapi::StringStream;
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

#include "codecs/HTMLEntityCodec.h"
using esapi::HTMLEntityCodec;

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
  // Positive test - uses the overload which takes a 'Char' character
  HTMLEntityCodec codec;

  struct KnownAnswer
  {
    int ch;
    NarrowString str;
  };

  // First and last 4 from entity table
  const KnownAnswer tests[] = {
    //{ 34, "&quot;" },
    //{ 38, "&amp;" },
    //{ 60, "&lt;" },
    //{ 62, "&gt;" },

    { 252, "&uuml;" },
    { 253, "&yacute;" },
    { 254, "&thorn;" },
    { 255, "&yuml;" }
  };

  StringArray immune;

  for( unsigned int i = 0; i < COUNTOF(tests); i++ )
  {
    const NarrowString utf8 = TextConvert::WideToNarrow(WideString(1,tests[i].ch));
    const NarrowString encoded = codec.encodeCharacter( immune, utf8 );
    const NarrowString expected = tests[i].str;

    StringStream oss;
    oss << "Failed to encode character. Expected ";
    oss << "'" << expected << "', got ";
    oss << "'" << encoded << "'";

    if(!(encoded == expected))
      cout << oss.str() << endl;
  }

	return 0;
}
