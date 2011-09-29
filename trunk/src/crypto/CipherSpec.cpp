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
 * @author Andrew Durkin, atdurkin@gmail.com
 *
 */

#include "EsapiCommon.h"
#include "crypto/CipherSpec.h"
#include "errors/IllegalArgumentException.h"
#include "util/SecureArray.h"
#include "util/TextConvert.h"

#include <algorithm>

namespace esapi
{

  void split(const String &str, const String& delim, StringArray& parts) //:This function is private to DefaultEncryptor.cpp.
  {                                                                            //:That should probably change but I don't know where is best to put it.
    String s(str);                                                             //:This class needs the function so a copy was put here temporarily.
    String::size_type pos = 0;

    while( (pos = s.find_first_of(delim)) != String::npos )
      {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos+1);
      }

    // Catch any tail bytes
    if( !s.empty() )
      parts.push_back(s);
  }

  CipherSpec::CipherSpec(const String& cipherXForm, int keySize, int blockSize, const SecureByteArray &iv)
  {
    setCipherTransformation(cipherXForm);
    setKeySize(keySize);
    setBlockSize(blockSize);
    setIV(iv);
  }

  CipherSpec::CipherSpec(const String& cipherXForm, int keySize, int blockSize)
  {
    setCipherTransformation(cipherXForm);
    setKeySize(keySize);
    setBlockSize(blockSize);
  }

  CipherSpec::CipherSpec(const String& cipherXForm, int keySize)
  {
    setCipherTransformation(cipherXForm);
    setKeySize(keySize);
    setBlockSize(16);
  }

  CipherSpec::CipherSpec(const String& cipherXForm, int keySize, const SecureByteArray &iv)
  {
    setCipherTransformation(cipherXForm);
    setKeySize(keySize);
    setBlockSize(16);
    setIV(iv);
  }

  CipherSpec::CipherSpec(const SecureByteArray &iv) //:In this constructor and one following, ESAPI class from Java version doesn't exist yet.
  {
    //setCipherTransformation(ESAPI.securityConfiguration().getCipherTransformation());
    //setKeySize(ESAPI.securityConfiguration().getEncryptionKeyLength());
    setBlockSize(16);
    setIV(iv);
  }

  CipherSpec::CipherSpec()
  {
    //setCipherTransformation(ESAPI.securityConfiguration().getCipherTransformation());
    //setKeySize(ESAPI.securityConfiguration().getEncryptionKeyLength());
    setBlockSize(16);
  }

  void CipherSpec::setCipherTransformation(const String& cipherXForm)
  {
    setCipherTransformation(cipherXForm, false);
  }

  void CipherSpec::setCipherTransformation(const String& cipherXForm, bool fromCipher)
  {
    String xform(cipherXForm);

    ASSERT(!xform.empty());
    if(xform.empty())
      throw IllegalArgumentException("Cipher transformation may not be null or empty string (after trimming whitespace)");

    StringArray parts;
    esapi::split(xform, L"/", parts);
    size_t numParts = parts.size();
    ESAPI_ASSERT2(fromCipher ? true : (numParts == 3), "Malformed cipherXform (" + TextConvert::WideToNarrow(xform) + "); must have form: \"alg/mode/paddingscheme\"");

    if(fromCipher && numParts != 3)
      {
        if(numParts == 1)
          xform += L"ECB/NoPadding";
        else if(numParts == 2)
          xform += L"/NoPadding";
        else
          throw IllegalArgumentException("Cipher transformation '" + TextConvert::WideToNarrow(xform) + "' must have form \"alg/mode/paddingscheme\"");
      }
    else if(!fromCipher && numParts != 3)
      throw IllegalArgumentException("Malformed xform (" + TextConvert::WideToNarrow(xform) + "); Must have form \"alg/mode/paddingscheme\"");
    ESAPI_ASSERT2(numParts == 3, "Implementation error in setCipherTransformation()");
    cipher_xform_ = xform;
  }

  String CipherSpec::getFromCipherXForm(CipherTransformationComponent component) const
  {
    std::vector<String> parts;
    String cipherXForm = this->getCipherTransformation();
    split(cipherXForm, L"/", parts);

    const NarrowString msg = "Invalid cipher transformation: " + TextConvert::WideToNarrow(getCipherTransformation());
    ESAPI_ASSERT2(parts.size() == 3, msg.c_str());
    return parts[component];
  }

  String CipherSpec::getCipherTransformation() const
  {
    return cipher_xform_;
  }

  void CipherSpec::setKeySize(int keySize)
  {
    ASSERT(keySize > 0);
    if(!(keySize > 0))
       throw IllegalArgumentException("KeySize must be > 0");

    keySize_ = keySize;
  }

  int CipherSpec::getKeySize() const
  {
    return keySize_;
  }

  void CipherSpec::setBlockSize(int blockSize)
  {
    ASSERT(blockSize > 0);
    if(!(blockSize > 0))
       throw IllegalArgumentException("BlockSize must be > 0");

    blockSize_ = blockSize;
  }

  int CipherSpec::getBlockSize() const
  {
    return blockSize_;
  }

  String CipherSpec::getCipherAlgorithm() const
  {
    return getFromCipherXForm(ALG);
  }

  String CipherSpec::getCipherMode() const
  {
    return getFromCipherXForm(MODE);
  }

  String CipherSpec::getPaddingScheme() const
  {
    return getFromCipherXForm(PADDING);
  }

  void CipherSpec::setIV(const SecureByteArray &iv)
  {
    ESAPI_ASSERT2(requiresIV() && !iv.empty(), "Required IV cannot be null or 0 length");
    iv_ = iv;
  }

  SecureByteArray CipherSpec::getIV() const
  {
    return iv_;
  }

  bool CipherSpec::requiresIV() const
  {
    String ciphmode = getCipherMode();
    std::transform(ciphmode.begin(), ciphmode.end(), ciphmode.begin(), ::tolower);
    if(ciphmode == L"ecb")
      return false;
    return true;
  }

  String CipherSpec::toString() const
  {
    WideStringStream strStm;
    strStm << L"CipherSpec: ";
    strStm << getCipherTransformation();
    strStm << L"; keySize = ";
    strStm << getKeySize();
    strStm << L" bits; blockSize = ";
    strStm << getBlockSize();
    strStm << L" bytes; IV Length = ";
    SecureByteArray iv = getIV();
    if(!iv.empty())
      strStm << iv.length() << L" bytes.";
    else
      strStm << L"[No IV present (not set or not required)].";
    return strStm.str();
  }

  bool CipherSpec::equals(const CipherSpec& obj) const //:In HashTrie.cpp, there's a line saying NullSafe isn't implemented yet, which breaks this function a bit.
  {
    /*
      if(NullSafe.equals(this->cipher_xform_, obj.cipher_xform_)
      && this->keySize == obj.keySize
      && this->blockSize == obj.blockSize
      && CryptoHelper.arrayCompare(this->iv_, obj.iv_))
      return true;
      return false;
    */
    if(this == &obj) return true;

    return false;
  }

} // NAMESPACE esapi
