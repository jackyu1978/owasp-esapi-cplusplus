/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 */

#include "util/AlgorithmName.h"

#include "EsapiCommon.h"
#include "util/TextConvert.h"
#include "errors/NoSuchAlgorithmException.h"
#include <algorithm>

namespace esapi
{
  // Private to this module
  static void split(const std::string& str, const std::string& delim, std::vector<std::string>& parts);

  AlgorithmName::AlgorithmName(const NarrowString& algorithm, bool cipherOnly)
    : m_normal(normalizeAlgorithm(algorithm))
  {
    ASSERT( !algorithm.empty() );

    // We'd prefer to throw in the ctor, but its a limitation, not a feature!
    // Actually, we need to narmalize first (in case of throw), so maybe it is a feature.
    NarrowString cipher;
    getCipher(cipher);

    if(cipherOnly && m_normal != cipher)
      throw NoSuchAlgorithmException(m_normal + " not available");
  }

  AlgorithmName::AlgorithmName(const WideString& algorithm, bool cipherOnly)
    : m_normal(TextConvert::WideToNarrow(normalizeAlgorithm(algorithm)))
  {
    ASSERT( !algorithm.empty() );

    // We'd prefer to throw in the ctor, but its a limitation, not a feature!
    // Actually, we need to narmalize first (in case of throw), so maybe it is a feature.
    NarrowString cipher;
    getCipher(cipher);

    if(cipherOnly && m_normal != cipher)
      throw NoSuchAlgorithmException(m_normal + " not available");
  }

  AlgorithmName::AlgorithmName(const AlgorithmName& rhs)
    : m_normal(rhs.m_normal)
  {
  }

  AlgorithmName& AlgorithmName::operator=(const AlgorithmName& rhs)
  {
    if(this != &rhs)
      {
        m_normal = rhs.m_normal;
      }
    return *this;
  }

  void AlgorithmName::getAlgorithm(NarrowString& algorithm) const
  {
    algorithm = m_normal;
  }

  void AlgorithmName::getAlgorithm(WideString& algorithm) const
  {
    algorithm = TextConvert::NarrowToWide(m_normal);
  }

  bool AlgorithmName::getCipher(NarrowString& cipher) const
  {
    std::vector<std::string> parts;
    split(m_normal, "\\/:", parts);

    if(parts.size() >= 1 && parts[0].length()) {
      cipher = parts[0];
      return true;
    }

    cipher = "";
    return false;
  }

  bool AlgorithmName::getCipher(WideString& cipher) const
  {
    std::string temp;
    if(getCipher(temp))
      {
        cipher = TextConvert::NarrowToWide(temp);
        return true;
      }

    cipher = L"";
    return false;
  }

  bool AlgorithmName::getMode(NarrowString& mode) const
  {
    std::vector<std::string> parts;
    split(m_normal, "\\/:", parts);

    if(parts.size() >= 2 && parts[1].length()) {
      mode = parts[1];
      return true;
    }

    mode = "";
    return false;
  }

  bool AlgorithmName::getMode(WideString& mode) const
  {
    std::string temp;
    if(getMode(temp))
      {
        mode = TextConvert::NarrowToWide(temp);
        return true;
      }

    mode = L"";
    return false;
  }

  bool AlgorithmName::getPadding(NarrowString& padding) const
  {
    std::vector<std::string> parts;
    split(m_normal, "\\/:", parts);

    if(parts.size() >= 3 && parts[2].length()) {
      padding = parts[2];
      return true;
    }

    padding = "";
    return false;
  }

  bool AlgorithmName::getPadding(WideString& padding) const
  {
    std::string temp;
    if(getPadding(temp))
      {
        padding = TextConvert::NarrowToWide(temp);
        return true;
      }

    padding = L"";
    return false;
  }

  void split(const std::string& str, const std::string& delim, std::vector<std::string>& parts)
  {
    std::string s(str);
    std::string::size_type pos = 0;

    while( (pos = s.find_first_of(delim)) != std::string::npos )
      {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos+1);
      }

    // Catch any tail bytes
    if( !s.empty() )
      parts.push_back(s);
  }

  WideString AlgorithmName::normalizeAlgorithm(const WideString& name)
  {
    NarrowString narrow = TextConvert::WideToNarrow(name);
    narrow = normalizeAlgorithm(narrow);
    return TextConvert::NarrowToWide(narrow);
  }

  NarrowString AlgorithmName::normalizeAlgorithm(const NarrowString& algorithm)
  {
    ASSERT(!algorithm.empty());

    NarrowString alg(algorithm), mode, padding, temp;

    // Cut out whitespace
    NarrowString::iterator it = std::remove_if(alg.begin(), alg.end(), ::isspace);
    if(it != alg.end())
      alg.erase(it, alg.end());

    // Save the trimmed string
    NarrowString trimmed(alg);

    // Normalize the case
    std::transform(alg.begin(), alg.end(), alg.begin(), ::tolower);

    std::vector<std::string> parts;
    split(alg, "\\/:", parts);

    if(parts.size() == 0)
      throw NoSuchAlgorithmException("Invalid transformation format: '<empty>'");

    // An algorithm is either CIPHER or CIPHER/MODE/PADDING
    if(!(parts.size() == 1 || parts.size() == 3))
      {
        std::ostringstream oss;
        oss << "Invalid transformation format: '" << trimmed << "'";
        throw NoSuchAlgorithmException(oss.str());
      }

    // Clear algorithm for final processing
    alg = mode = padding = "";

    // We should see a CIPHER (ie, HmacSHA1), or a CIPHER/MODE/PADDING.
    temp = parts[0];

    //////// Symmetric Ciphers ////////

    if(temp == "aes")
      alg = "AES";
    else if(temp == "camellia")
      alg = "Camellia";
    else if(temp == "blowfish")
      alg = "Blowfish";
    else if(temp == "des_ede" || temp == "desede")
      alg = "DES_ede";
    else if(temp == "des")
      alg = "DES";

    //////// Hashes ////////

    else if(temp == "md-5" || temp == "md5")
      alg = "MD5";
    else if(temp == "sha-1" || temp == "sha1" || temp == "sha")
      alg = "SHA-1";
    else if(temp == "sha-224" || temp == "sha224")
      alg = "SHA-224";
    else if(temp == "sha-256" || temp == "sha256")
      alg = "SHA-256";
    else if(temp == "sha-384" || temp == "sha384")
      alg = "SHA-384";
    else if(temp == "sha-512" || temp == "sha512")
      alg = "SHA-512";
    else if(temp == "whirlpoo")
      alg = "Whirlpoo";

    //////// HMACs ////////

    else if(temp == "hmacsha-1" || temp == "hmacsha1" || temp == "hmacsha")
      alg = "HmacSHA1";
    else if(temp == "hmacsha-224" || temp == "hmacsha224")
      alg = "HmacSHA224";
    else if(temp == "hmacsha-256" || temp == "hmacsha256")
      alg = "HmacSHA256";
    else if(temp == "hmacsha-384" || temp == "hmacsha384")
      alg = "HmacSHA384";
    else if(temp == "hmacsha-512" || temp == "hmacsha512")
      alg = "HmacSHA512";
    else if(temp == "hmacwhirlpoo")
      alg = "HmacWhirlpoo";

    //////// PBE Hmacs ////////

    else if(temp == "pbewithsha1")
      alg = "PBEWithSHA1";
    else if(temp == "pbewithsha224")
      alg = "PBEWithSHA224";
    else if(temp == "pbewithsha256")
      alg = "PBEWithSHA256";
    else if(temp == "pbewithsha384")
      alg = "PBEWithSHA384";
    else if(temp == "pbewithsha512")
      alg = "PBEWithSHA512";
    else if(temp == "pbewithwhirlpoo")
      alg = "PBEWithWhirlpoo";

    //////// Key Agreement ////////

    else if(temp == "diffiehellman")
      alg = "DiffieHellman";

    //////// SecureRandom ////////

    else if(temp == "sha1prng")
      alg = "SHA1PRNG";

    //////// Oh shit! ////////

    else {
      std::ostringstream oss;
      oss << "Invalid transformation format: '" << trimmed << "', cipher '" << temp << "'";
      ESAPI_ASSERT2(false, oss.str());
      throw NoSuchAlgorithmException(oss.str());
    }

    if(parts.size() == 1)
      return alg;

    // Mode
    temp = parts[1];

    if(temp == "none")
      mode = "NONE";
    else if(temp == "ecb")
      mode = "ECB";
    else if(temp == "cbc")
      mode = "CBC";
    else if(temp == "ofb")
      mode = "OFB";
    else if(temp == "cfb")
      mode = "CFB";
    else if(temp == "ctr")
      mode = "CTR";
#if 0
    // Uncomment in the future
    else if(temp == "ccm")
      mode = "CCM";
    else if(temp == "gcm")
      mode = "GCM";
    else if(temp == "eax")
      mode = "EAX";
#endif

    else {
      std::ostringstream oss;
      oss << "Invalid transformation format: '" << trimmed << "', mode '" << temp << "'";
      ESAPI_ASSERT2(false, oss.str());
      throw NoSuchAlgorithmException(oss.str());
    }

    // Padding
    temp = parts[2];

    if(temp == "nopadding" || temp == "none")
      padding = "NoPadding";
    else if(temp == "pkcs5padding")
      padding = "PKCS5Padding";
    else if(temp == "ssl3padding")
      padding = "SSL3Padding";

    else {
      std::ostringstream oss;
      oss << "Invalid transformation format: '" << trimmed << "', padding '" << temp << "'";
      ESAPI_ASSERT2(false, oss.str());
      throw NoSuchAlgorithmException(oss.str());
    }

    // Remove if we ever get around to adding SSL3 padding.
    if(padding == "SSL3Padding") {
      std::ostringstream oss;
      oss << "Unsupported transformation format: '" << trimmed << "', padding '" << temp << "'";
      throw NoSuchAlgorithmException(oss.str());
    }

    // Final return string
    alg += "/" + mode;
    alg += "/" + padding;

    return alg;
  }

} // NAMESPACE
