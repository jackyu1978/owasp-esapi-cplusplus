/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author kevin.w.wall@gmail.com
 * @author noloader@gmail.com
 *
 */

#include "EsapiCommon.h"
#include "crypto/KeyGenerator.h"
#include "crypto/SecretKey.h"

#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

#include <cryptopp/aes.h>
#include <cryptopp/des.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/modes.h>

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

/**
 * This class implements functionality similar to Java's KeyGenerator for consistency
 */
namespace esapi
{
  template <class CIPHER, template <class CIPHER> class MODE>
  void BlockCipherGenerator<CIPHER, MODE>::init(unsigned int keySize)
  {
    m_keySize = keySize;
  }

  template <class CIPHER, template <class CIPHER> class MODE>
  std::string BlockCipherGenerator<CIPHER, MODE>::algorithm() const
  {
    return m_algorithm;
  }

  // Sad, but true. m_cipher does not cough up its name
  template <class CIPHER, template <class CIPHER> class MODE>
  BlockCipherGenerator<CIPHER, MODE>::BlockCipherGenerator(const std::string& algorithm)
  {
    m_algorithm = algorithm;
  }

  // Called by base class KeyGenerator::getInstance
  template <class CIPHER, template <class CIPHER> class MODE>
  KeyGenerator* BlockCipherGenerator<CIPHER, MODE>::CreateInstance(const std::string& algorithm)
  {
    return new BlockCipherGenerator<CIPHER, MODE>(algorithm);
  }

  template <class CIPHER, template <class CIPHER> class MODE>
  esapi::SecretKey BlockCipherGenerator<CIPHER, MODE>::generateKey()
  {
    return esapi::SecretKey(m_keySize);
  }

  ///////////////////////////////////////////////////////////////////////////////////

  const std::string KeyGenerator::DefaultAlgorithm = "AES/CFB";
  const unsigned int KeyGenerator::DefaultKeySize = 128;

  KeyGenerator* KeyGenerator::getInstance(const std::string& algorithm)
  {
    std::string alg = algorithm, mode;
    std::string::size_type pos;

    // Normalize the case
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    // Normalize the slashes
    while(std::string::npos != (pos = alg.find('\\')))
        alg.replace(pos, 1, "/");

    // Remove the '/' and anything that follows
    if(std::string::npos != (pos = alg.find('/')))
    {
        mode = alg.substr(pos+1, -1);
        alg.erase(pos, -1);
    }

    // Lop off anything remaining
    if(std::string::npos != (pos = mode.find('/')))
        mode.erase(pos, -1);

    // Form the name returned by algorithm()
    std::string name = alg;
	if(!alg.empty() && !mode.empty())
		name += "/" + mode;

    std::transform(name.begin(), name.end(), name.begin(), ::toupper);

    // http://download.oracle.com/javase/6/docs/technotes/guides/security/SunProviders.html

    if(alg == "aes")
      return BlockCipherGenerator<CryptoPP::AES, CryptoPP::CBC_Mode>::CreateInstance(name);

    if(alg == "blowfish")
      return BlockCipherGenerator<CryptoPP::Blowfish, CryptoPP::CBC_Mode>::CreateInstance(name);

    if(alg == "desede")
      return BlockCipherGenerator<CryptoPP::DES_EDE3, CryptoPP::CBC_Mode>::CreateInstance(name);

    std::ostringstream oss;
    oss << "Algorithm specification \'" << algorithm << "\' is not supported.";
    throw std::invalid_argument(oss.str());

    // This should really be declared __no_return__
    return nullptr;
  }
   
} // NAMESPACE esapi
