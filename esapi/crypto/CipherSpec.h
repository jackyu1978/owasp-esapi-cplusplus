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

/**
 * Specifies all the relevant configuration data needed in constructing and
 * using a {@link javax.crypto.Cipher} except for the encryption key.
 * </p><p>
 * The "setters" all return a reference to {@code this} so that they can be
 * strung together.
 * </p><p>
 * Note: While this is a useful class in it's own right, it should primarily be
 * regarded as an implementation class to use with ESAPI encryption, especially
 * the reference implementation. It is <i>not</i> intended to be used directly
 * by application developers, but rather only by those either extending ESAPI
 * or in the ESAPI reference implementation. Use <i>directly</i> by application
 * code is not recommended or supported.
 *
 **/

namespace esapi
{

class ESAPI_EXPORT CipherSpec
{
private:
     String cipher_xform_; //:Cipher Transformation, takes form of "ALG/MODE/PADDING"
     int keySize_; //:The key size, IN BITS.
     int blockSize_; //:The block size, IN BYTES.
     SecureByteArray iv_; //:The initialization vector, NULL if not applicable
     enum CipherTransformationComponent {ALG, MODE, PADDING}; //:Cipher transformation component. Format is ALG/MODE/PADDING.
     void setCipherTransformation(String cipherXForm, bool fromCipher);
     String getFromCipherXForm(CipherTransformationComponent component);
public:
     CipherSpec(String cipherXForm, int keySize, int blockSize, const SecureByteArray &iv); //:Explicitly sets everything.
     CipherSpec(String cipherXForm, int keySize, int blockSize); //:Sets everything but IV.
     CipherSpec(String cipherXForm, int keySize); //:Sets everything but blockSize and IV
     CipherSpec(String cipherXForm, int keySize, const SecureByteArray &iv); //:Sets everything but blockSize.
     //CipherSpec(Cipher cipher);             //:Cipher class is Java specific, not sure if a C++ version is being used
     //CipherSpec(Cipher cipher, int keySize);
     CipherSpec(const SecureByteArray &iv); //:Sets only iv
     CipherSpec(); //:Created because of an error in another file.
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
     String toString(); //:Returns a meaningful {@code String} describing the object.
     bool equals(CipherSpec obj);
};

} // NAMESPACE esapi
