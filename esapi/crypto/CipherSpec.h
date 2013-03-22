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
 * the reference implementation. It is <i>not</i> unsigned intended to be used directly
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
    unsigned int keySize_; //:The key size, IN BITS.
    unsigned int blockSize_; //:The block size, IN BYTES.
    SecureByteArray iv_; //:The initialization vector, NULL if not applicable
    enum CipherTransformationComponent {ALG, MODE, PADDING}; //:Cipher transformation component. Format is ALG/MODE/PADDING.
    String getFromCipherXForm(CipherTransformationComponent component) const;
  public:
    CipherSpec(const NarrowString& cipherXForm, unsigned int keySize, unsigned int blockSize, const SecureByteArray &iv); //:Explicitly sets everything.
    CipherSpec(const NarrowString& cipherXForm, unsigned int keySize, unsigned int blockSize); //:Sets everything but iv.
    CipherSpec(const NarrowString& cipherXForm, unsigned int keySize); //:Sets everything but blockSize and iv.
    CipherSpec(const NarrowString& cipherXForm, unsigned int keySize, const SecureByteArray &iv); //:Sets everything but blockSize.
    CipherSpec(const SecureByteArray &iv); //:Sets only iv
    CipherSpec(const CipherSpec &cs); //:Copy CTOR.
    CipherSpec();

    CipherSpec& operator=(const CipherSpec& cs); //:Assignment.
    String verifyCipherXForm(const NarrowString& cipherXForm); //:Verifies CipherXForm format matches "ALG/MODE/PAD".
    void setCipherTransformation(const NarrowString& cipherXForm);
    String getCipherTransformation() const;
    void setKeySize(unsigned int keySize);
    unsigned int getKeySize() const;
    void setBlockSize(unsigned int blockSize);
    unsigned int getBlockSize() const;
    String getCipherAlgorithm() const;
    String getCipherMode() const;
    String getPaddingScheme() const;
    void setIV(const SecureByteArray &iv);
    SecureByteArray getIV() const;
    bool requiresIV() const;
    String toString() const; //:Returns a meaningful {@code String} describing the object.
    bool equals(const CipherSpec& obj) const; //:Comparison between CipherSpecs
  };

} // NAMESPACE esapi

