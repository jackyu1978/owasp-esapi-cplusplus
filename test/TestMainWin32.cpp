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
	//MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
	bool success = false;
	MessageDigest md(MessageDigest::getInstance("MD5"));

	const size_t sz = md.getDigestLength();
	SecureByteArray buf(sz);

	const String msg("abc");
	md.update(msg);

	const byte hash[16] = {0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72};
	md.digest(buf.data(), buf.size(), 0, sz);
	success = (::memcmp(buf.data(), hash, sizeof(hash)) == 0);

	return 0;
}
