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
#include "errors/IllegalArgumentException.h"
#include "errors/NoSuchAlgorithmException.h"
#include <algorithm>

namespace esapi
{
  // Private to this module
  static void split(const std::string& str, const std::string& delim, std::vector<std::string>& parts);

  AlgorithmName::AlgorithmName(const NarrowString& algorithm)
    : m_normal(normalizeAlgorithm(algorithm))
  {
    ASSERT( !algorithm.empty() );
  }

  AlgorithmName::AlgorithmName(const WideString& algorithm)
    : m_normal(TextConvert::WideToNarrow(normalizeAlgorithm(algorithm)))
  {
    ASSERT( !algorithm.empty() );
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

  void AlgorithmName::getAlgorithm(NarrowString& normal) const
  {
    normal = m_normal;
  }

  void AlgorithmName::getAlgorithm(WideString& normal) const
  {
    normal = TextConvert::NarrowToWide(m_normal);
  }

  bool AlgorithmName::getCipher(NarrowString& cipher) const
  {
    std::vector<std::string> parts;
    split(m_normal, "\\/:", parts);

    if(parts.size() >= 1 && parts[0].length()) {
      cipher = parts[0];
      return true;
    }
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

    return false;
  }

  void split(const std::string& str, const std::string& delim, std::vector<std::string>& parts)
  {
    std::string s(str);
    std::string::size_type pos = 0;

    while( (pos = s.find_first_of(delim)) != String::npos )
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
      throw IllegalArgumentException("The algorithm is empty");

    // Clear algorithm for final processing
    alg = mode = padding = "";
    bool bad = false;

    // We should see a CIPHER (ie, HmacSHA1), or a CIPHER/MODE/PADDING.
    if(parts.size() >= 1)
      {
        temp = parts[0];

        //////// Symmetric Ciphers ////////

        if(temp == "aes")
          alg = "AES";
        else if(temp == "aes128")
          alg = "AES128";
        else if(temp == "aes192")
          alg = "AES192";
        else if(temp == "aes256")
          alg = "AES256";

        else if(temp == "camellia")
          alg = "Camellia";
        else if(temp == "camellia128")
          alg = "Camellia128";
        else if(temp == "camellia192")
          alg = "Camellia192";
        else if(temp == "camellia256")
          alg = "Camellia256"; 

        else if(temp == "blowfish")
          alg = "Blowfish";

        else if(temp == "desede")
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
        else if(temp == "whirlpool")
          alg = "Whirlpool";

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
        else if(temp == "hmacwhirlpool")
          alg = "HmacWhirlpool";

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
        else if(temp == "pbewithshawhirlpool")
          alg = "PBEWithWhirlpool";

        //////// Key Agreement ////////

        else if(temp == "diffiehellman")
          alg = "DiffieHellman";

        //////// Oh shit! ////////

        else {
          bad = true;

          std::ostringstream oss;
          oss << "Cipher '" << temp << "' is not valid";
          ESAPI_ASSERT2(false, oss.str());
        }
      }

    if(parts.size() >= 2)
      {
        temp = parts[1];

        if(temp == "none")
          mode = "NONE";
        else if(temp == "ecb")
          mode = "ECB";
        else if(temp == "cbc")
          mode = "CBC";
        else if(temp == "ccm")
          mode = "CCM";
        else if(temp == "gcm")
          mode = "GCM";
        else if(temp == "eax")
          mode = "EAX";
        else if(temp == "ofb")
          mode = "OFB";
        else if(temp == "cfb")
          mode = "CFB";
        else if(temp == "ctr")
          mode = "CTR";

        else {
          bad = true;

          std::ostringstream oss;
          oss << "Mode '" << temp << "' is not valid";
          ESAPI_ASSERT2(false, oss.str());
        }
      }

    if(parts.size() >= 3)
      {
        temp = parts[2];

        if(temp == "nopadding" || temp == "none")
          padding = "NoPadding";
        else if(temp == "pkcs5padding")
          padding = "PKCS5Padding";
        else if(temp == "ssl3padding")
          padding = "SSL3Padding";

        else {
          bad = true;

          std::ostringstream oss;
          oss << "Padding '" << temp << "' is not valid";
          ESAPI_ASSERT2(false, oss.str());
        }
      }

    // If there was any 'extra' information, such as an additional
    // trailing slash and data, flag it now
    if(parts.size() >= 4)
    {
      bad = true;

      std::ostringstream oss;
      oss << "Additional data '" << parts[3] << "' is not expected or valid";
      ESAPI_ASSERT2(false, oss.str());
    }

    if(bad)
    {
      std::ostringstream oss;
      oss << "Algorithm '" << trimmed << "' is not valid";
      throw NoSuchAlgorithmException(oss.str());
    }

    // Final return string
    NarrowString result(alg);
    if(mode.length()) { result += "/" + mode; }
    if(padding.length()) { result += "/" + padding; }

    return result;
  }

} // NAMESPACE
