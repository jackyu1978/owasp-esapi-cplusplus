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

#pragma once

#include "EsapiCommon.h"
#include "util/SecureArray.h"

namespace esapi
{

class ESAPI_EXPORT CipherSpec
{
private:
     String cipher_xform_;
     int keySize_;
     int blockSize_;
     SecureByteArray iv_;
     enum CipherTransformationComponent {ALG, MODE, PADDING};
     void setCipherTransformation(String cipherXForm, bool fromCipher);
     String getFromCipherXForm(CipherTransformationComponent component);
public:
     CipherSpec(String cipherXForm, int keySize, int blockSize, const SecureByteArray &iv);
     CipherSpec(String cipherXForm, int keySize, int blockSize);
     CipherSpec(String cipherXForm, int keySize);
     CipherSpec(String cipherXForm, int keySize, const SecureByteArray &iv);
     //CipherSpec(Cipher cipher);
     //CipherSpec(Cipher cipher, int keySize);
     CipherSpec(const SecureByteArray &iv);
     CipherSpec();
     void setCipherTransformation(String cipherXForm);
     String getCipherTransformation();
     void setKeySize(int keySize);
     int getKeySize();
     void setBlockSize(int blockSize);
     int getBlockSize();
     String getCipherAlgorithm();
     String getCipherMode();
     String getPaddingScheme();
     void setIV(const SecureByteArray &iv);
     SecureByteArray getIV();
     bool requiresIV();
     String toString();
     //bool equals(CipherSpec obj);
};

}; //NAMESPACE esapi
