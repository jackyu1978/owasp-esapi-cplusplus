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

  CipherSpec::CipherSpec(const String& cipherXForm, unsigned int keySize, unsigned int blockSize, const SecureByteArray &iv)
    : cipher_xform_(verifyCipherXForm(cipherXForm)), keySize_(keySize), blockSize_(blockSize), iv_(iv)
  {
    ASSERT( keySize > 0 );
    ASSERT( blockSize > 0 );
    ASSERT( iv.size() > 0 );
  }

  CipherSpec::CipherSpec(const String& cipherXForm, unsigned int keySize, unsigned int blockSize)
    : cipher_xform_(verifyCipherXForm(cipherXForm)), keySize_(keySize), blockSize_(blockSize)
  {
    ASSERT( keySize > 0 );
    ASSERT( blockSize > 0 );
  }

  CipherSpec::CipherSpec(const String& cipherXForm, unsigned int keySize)
    : cipher_xform_(verifyCipherXForm(cipherXForm)), keySize_(keySize), blockSize_(16)
  {
    ASSERT( keySize > 0 );
  }

  CipherSpec::CipherSpec(const String& cipherXForm, unsigned int keySize, const SecureByteArray &iv)
    : cipher_xform_(verifyCipherXForm(cipherXForm)), keySize_(keySize), blockSize_(16), iv_(iv)
  {
    ASSERT( keySize > 0 );
    ASSERT( iv.size() > 0 );
  }

  CipherSpec::CipherSpec(const SecureByteArray &iv) //:In this constructor and one following, ESAPI class from Java version doesn't exist yet.
  //: cipher_xform_(ESAPI.securityConfiguration().getCipherTransformation()), keySize_(ESAPI.securityConfiguration().getEncryptionKeyLength()), blockSize_(16), iv_(iv)
  {
    ASSERT( iv.size() > 0 );
    //setCipherTransformation(ESAPI.securityConfiguration().getCipherTransformation());
    //setKeySize(ESAPI.securityConfiguration().getEncryptionKeyLength());
    setBlockSize(16);
    setIV(iv);
  }

  CipherSpec::CipherSpec()
  //: cipher_xform_(ESAPI.securityConfiguration().getCipherTransformation()), keySize_(ESAPI.securityConfiguration().getEncryptionKeyLength()), blockSize_(16)
  {
    //setCipherTransformation(ESAPI.securityConfiguration().getCipherTransformation());
    //setKeySize(ESAPI.securityConfiguration().getEncryptionKeyLength());
    setBlockSize(16);
  }

  String CipherSpec::verifyCipherXForm(const String& cipherXForm)
  {
    ASSERT(!cipherXForm.empty());

    String xform(cipherXForm);
    if(xform.empty())
      throw IllegalArgumentException("Cipher transformation may not be null or empty string (after trimming whitespace)");

    StringArray parts;
    esapi::split(xform, L"/", parts);
    size_t numParts = parts.size();
    ESAPI_ASSERT2(numParts == 3, "Malformed cipherXform (" + TextConvert::WideToNarrow(xform) + "); must have form: \"alg/mode/paddingscheme\"");

    if(numParts != 3)
      {
        throw IllegalArgumentException("Cipher transformation '" + TextConvert::WideToNarrow(xform) + "' must have form \"alg/mode/paddingscheme\"");
        if(numParts == 1)
          xform += L"ECB/NoPadding";
        else if(numParts == 2)
          xform += L"/NoPadding";
        else //:If it gets here, something's way off with the passed cipherXForm, so, set it to default. Getting here has already set off an exception above.
          xform = L"ALG/MODE/PADDING"; //ESAPI.securityConfiguration().getCipherTransformation();
      }
    ESAPI_ASSERT2(numParts == 3, "Implementation error in verifyCipherXForm()");
    return xform;
  }

  void CipherSpec::setCipherTransformation(const String& cipherXForm)
  {
    cipher_xform_ = verifyCipherXForm( cipherXForm );
  }

  String CipherSpec::getCipherTransformation() const
  {
    return cipher_xform_;
  }

  String CipherSpec::getFromCipherXForm(CipherTransformationComponent component) const
  {
    String xform = this->getCipherTransformation();
    ASSERT( !xform.empty() );

    StringArray parts;
    split(xform, L"/", parts);

    const NarrowString msg = "Invalid cipher transformation: " + TextConvert::WideToNarrow(xform);
    ESAPI_ASSERT2(parts.size() == 3, msg.c_str());

    if((parts.size() >= (unsigned)component))
      return parts[component];
    else
      return L"";
  }

  void CipherSpec::setKeySize(int keySize)
  {
    ASSERT(keySize > 0);
    if(!(keySize > 0))
       throw IllegalArgumentException("KeySize must be greater than 0");

    keySize_ = keySize;
  }

  unsigned int CipherSpec::getKeySize() const
  {
    ASSERT(keySize_ > 0);
    return keySize_;
  }

  void CipherSpec::setBlockSize(unsigned int blockSize)
  {
    ASSERT(blockSize > 0);
    if(!(blockSize > 0))
      throw IllegalArgumentException("BlockSize must be greater than 0");
    blockSize_ = blockSize;
  }

  unsigned int CipherSpec::getBlockSize() const
  {
    ASSERT(blockSize_ > 0);
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

  bool CipherSpec::requiresIV() const
  {
    String ciphmode = this->getCipherMode();
    std::transform(ciphmode.begin(), ciphmode.end(), ciphmode.begin(), ::tolower);
    if(ciphmode == L"ecb")
      return false;
    return true;
  }

  void CipherSpec::setIV(const SecureByteArray &iv)
  {
    SecureByteArray ivCopy(iv);
    ESAPI_ASSERT2((this->requiresIV() && !ivCopy.empty()), "Required IV cannot be null or 0 length");
    iv_ = ivCopy;
  }

  SecureByteArray CipherSpec::getIV() const
  {
    return SecureByteArray(iv_);
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
