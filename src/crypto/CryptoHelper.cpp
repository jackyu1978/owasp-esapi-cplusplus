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

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"
#include "crypto/KeyGenerator.h"
#include "crypto/CryptoHelper.h"
#include "crypto/Crypto++Common.h"
#include "crypto/KeyDerivationFunction.h"

#include "safeint/SafeInt3.hpp"

#include <memory>
#include <stdexcept>

/**
 * This class implements functionality similar to Java's CryptoHelper for consistency
 */
namespace esapi
{
  // TODO: Also consider supplying implementation of RFC 2898 / PKCS#5 PBKDF2
  //         in this file as well??? Maybe save for ESAPI 2.1 or 3.0.

  // Tames the optimizer
  static volatile void* g_dummy = nullptr;

  /**
   * Generate a random secret key appropriate to the specified cipher algorithm
   * and key size.
   * @param alg        The cipher algorithm or cipher transformation. (If the latter is
   *                   passed, the cipher algorithm is determined from it.) Cannot be empty.
   * @param keyBits    The key size, in bits.
   * @return           A random {@code SecretKey} is returned.
   */
  SecretKey CryptoHelper::generateSecretKey(const std::string& alg, unsigned int keyBits)
  {
    ASSERT( !alg.empty() );
    ASSERT( keyBits >= 56 );
    ASSERT( (keyBits % 8) == 0 );

    KeyGenerator kgen(KeyGenerator::getInstance(alg));
    kgen.init(keyBits);

    return kgen.generateKey();
  }

  /**
   * The ESAPI Key Derivation Function (KDF) that computes a derived key from
   * the {@code keyDerivationKey} for either encryption, decryption, or authentication.
   * <p>
   * <b>CAUTION:</b> If this algorithm for computing derived keys from the key derivation key
   * is <i>ever</i> changed, we risk breaking backward compatibility of being able to decrypt
   * data previously encrypted with earlier / different versions of this method. Therefore,
   * do not change this unless you are 100% certain that what you are doing will NOT change
   *  either of the derived keys for ANY "key derivation key" AT ALL!!!
   * <p>
   * <b>NOTE:</b> This method is generally not intended to be called separately.
   * It is used by ESAPI's reference crypto implementation class {@code JavaEncryptor}
   * and might be useful for someone implementing their own replacement class, but
   * generally it is not something that is useful to application client code.
   * 
   * @param keyDerivationKey  A key used as an input to a key derivation function
   *                          to derive other keys. This is the key that generally
   *                          is created using some key generation mechanism such as
   *                          {@link #generateSecretKey(String, int)}. The
   *                          "input" key from which the other keys are derived.
   *                          The derived key will have the same algorithm type
   *                          as this key.
   * @param keyBits       The cipher's key size (in bits) for the {@code keyDerivationKey}.
   *                      Must have a minimum size of 56 bits and be an integral multiple of 8-bits.
   *                      <b>Note:</b> The derived key will have the same size as this.
   * @param purpose       The purpose or use for the derived key. Must be either the
   *                      string "encryption" or "authenticity". Use "encryption" for
   *                      creating a derived key to use for confidentiality, and "authenticity"
   *                      for a derived key to use with a MAC to ensure message authenticity.
   *                      Note that the parameter "purpose" serves the same function as "label" 
   *                      in section 5.1 of NIST SP 800-108.
   * @return              The derived {@code SecretKey} to be used according
   *                      to the specified purpose.
   * @deprecated Use{@code KeyDerivationFunction} instead. This method will be removed as of
   *                ESAPI release 2.1 so if you are using this, please change your code.
   */
  SecretKey CryptoHelper::computeDerivedKey(const SecretKey keyDerivationKey, unsigned int keyBits, const std::string& purpose)
  {
    // Shamelessly ripped from KeyDerivationFunction.cpp
    ASSERT( keyDerivationKey.sizeInBytes()  > 0 );
    ASSERT( keyBits >= 56 );
    ASSERT( (keyBits % 8) == 0 );
    ASSERT( purpose == "authenticity" || purpose == "encryption" );

    return KeyDerivationFunction::computeDerivedKey(keyDerivationKey, keyBits, purpose);
  }

  /**
   * Return true if specified cipher mode is one of those specified in the
   * {@code ESAPI.properties} file that supports both confidentiality
   * <b>and</b> authenticity (i.e., a "combined cipher mode" as NIST refers
   * to it).
   * @param cipherMode     The specified cipher mode to be used for the encryption
   *                       or decryption operation.
   * @return     true if the specified cipher mode is in the comma-separated list
   *             of cipher modes supporting both confidentiality and authenticity;
   *             otherwise false.
   * @see org.owasp.esapi.SecurityConfiguration#getCombinedCipherModes()
   */
  bool CryptoHelper::isCombinedCipherMode(const std::string& cipherMode)
  {
    ASSERT(!cipherMode.empty());

    ASSERT(0);
    return false;
  }

  /**
   * Return true if specified cipher mode may be used for encryption and
   *   decryption operations via {@link org.owasp.esapi.Encryptor}.
   * @param cipherMode The specified cipher mode to be used for the encryption
   *                   or decryption operation.
   * @return true if the specified cipher mode is in the comma-separated list
   *         of cipher modes supporting both confidentiality and authenticity;
   *         otherwise false.
   * @see #isCombinedCipherMode(String)
   * @see org.owasp.esapi.SecurityConfiguration#getCombinedCipherModes()
   * @see org.owasp.esapi.SecurityConfiguration#getAdditionalAllowedCipherModes()
   */
  bool CryptoHelper::isAllowedCipherMode(const std::string& cipherMode)
  {
    ASSERT(!cipherMode.empty());

    ASSERT(0);
    return false;
  }

  /**
   * Check to see if a Message Authentication Code (MAC) is required
   * for a given {@code CipherText} object and the current ESAPI.property
   * settings. A MAC is considered "required" if the specified
   * {@code CipherText} was not encrypted by one of the preferred
   * "combined" cipher modes (e.g., CCM or GCM) and the setting of the
   * current ESAPI properties for the property
   * {@code Encryptor.CipherText.useMAC} is set to {@code true}. (Normally,
   * the setting for {@code Encryptor.CipherText.useMAC} should be set to
   * {@code true} unless FIPS 140-2 compliance is required. See
   * <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-symmetric-crypto-user-guide.html">
   * User Guide for Symmetric Encryption in ESAPI 2.0</a> and the section
   * on using ESAPI with FIPS for further details.
   *
   * @param cipherText    The specified {@code CipherText} object to check to see if
   *                      it requires a MAC.
   * @returns             True if a MAC is required, false if it is not required.
   */
  bool CryptoHelper::isMACRequired(const CipherText& cipherText)
  {
    ASSERT(!cipherText.empty());

    ASSERT(0);
    return false;
  }

  /**
   * If a Message Authentication Code (MAC) is required for the specified
   * {@code CipherText} object, then attempt to validate the MAC that
   * should be embedded within the {@code CipherText} object by using a
   * derived key based on the specified {@code SecretKey}.
   *
   * @param secretKey   The {@code SecretKey} used to derived a key to check
   *                    the authenticity via the MAC.
   * @param cipherText  The {@code CipherText} that we are checking for a
   *                    valid MAC. 
   *
   * @return  True is returned if a MAC is required and it is valid as
   *          verified using a key derived from the specified
   *          {@code SecretKey} or a MAC is not required. False is returned
   *          otherwise.
   */
  bool CryptoHelper::isCipherTextMACvalid(const SecretKey& secretKey, const CipherText& cipherText)
  {
    ASSERT(secretKey.sizeInBytes() > 0);
    ASSERT(!cipherText.empty());

    ASSERT(0);
    return false;
  }

  /**
   * Overwrite a byte array with a specified byte. This is frequently done
   * to a plaintext byte array so the sensitive data is not lying around
   * exposed in memory.
   * @param bytes    The byte array to be overwritten.
   * @param size     The size of the byte array.
   * @param x        The byte array {@code bytes} is overwritten with this byte.
   */
  void CryptoHelper::overwrite(byte bytes[], size_t size, byte x)
  {
    ASSERT(bytes);
    ASSERT(size);

    if(!bytes)
      throw std::invalid_argument("The array cannot be null or empty");

    if(!size)
      return;

    // Will throw if ptr wraps. T* and size_t causing trouble on Linux
    SafeInt<size_t> si((size_t)bytes); si += size;
    g_dummy = (void*)(size_t)si;

    for(size_t i = 0; i < size; i++)
      bytes[i] = x;

    // Tame the otpimizer
    g_dummy = bytes;
  }

  /**
   * Overwrite a byte array with the byte containing '*'. That is, call
   * <pre>
   *         overwrite(bytes, (byte)'*');
   * </pre>
   * @param bytes    The byte array to be overwritten.
   * @param size     The size of the byte array.
   */
  void CryptoHelper::overwrite(byte bytes[], size_t size)
  {
    ASSERT(bytes);
    ASSERT(size);

    // The called overload tests for ptr wrap
    overwrite(bytes, size, '*');
  }

  // These provide for a bit more type safety when copying bytes around.
  /**
   * Same as {@code System.arraycopy(src, 0, dest, 0, length)}.
   * 
   * @param      src       the source array.
   * @param      srcSize   the size of the source array.
   * @param      dest      the destination array.
   * @param      destSize  the size of the destination array.
   * @param      length    the number of array elements to be copied.
   */
  void CryptoHelper::copyByteArray(const byte src[], size_t srcSize, byte dest[], size_t destSize, size_t copySize)
  {
    ASSERT(src);
    ASSERT(srcSize);
    ASSERT(dest);
    ASSERT(destSize);
    ASSERT(srcSize >= copySize);
    ASSERT(destSize >= copySize);

    if(!src)
      throw std::invalid_argument("Source array cannot be null");

    if(!dest)
      throw std::invalid_argument("Destination array cannot be null");

    // Will throw if ptr wraps. T* and size_t causing trouble on Linux
    SafeInt<size_t> ssi((size_t)src); ssi += srcSize;
    g_dummy = (void*)(size_t)ssi;
    SafeInt<size_t> dsi((size_t)dest); dsi += destSize;
    g_dummy = (void*)(size_t)dsi;

    const size_t req = std::min(copySize, std::min(srcSize, destSize));
    ASSERT(req > 0);

    if(req < copySize)
      throw std::out_of_range("Copy size exceeds source or destination size");
        
    ESAPI_MS_NO_WARNING(4996);
    std::copy(src, src+req, dest);
    ESAPI_MS_DEF_WARNING(4996);
  }

  /**
   * Same as {@code copyByteArray(src, dest, src.length)}.
   * @param      src       the source array.
   * @param      srcSize   the size of the source array.
   * @param      dest      the destination array.
   * @param      destSize  the size of the destination array.
   */
  void CryptoHelper::copyByteArray(const byte src[], size_t srcSize, byte dest[], size_t destSize)
  {
    ASSERT(src);
    ASSERT(srcSize);
    ASSERT(dest);
    ASSERT(destSize);
    ASSERT(destSize >= srcSize);

    // The called overload tests for ptr wrap
    return copyByteArray(src, srcSize, dest, destSize, srcSize);
  }

  /**
   * A "safe" array comparison that is not vulnerable to side-channel
   * "timing attacks". All comparisons of non-null, equal length bytes should
   * take same amount of time. We use this for cryptographic comparisons.
   * 
   * @param b1   A byte array to compare.
   * @param b2   A second byte array to compare.
   * @return     {@code true} if both byte arrays are null or if both byte
   *             arrays are identical or have the same value; otherwise
   *             {@code false} is returned.
   */
  bool CryptoHelper::arrayCompare(const byte b1[], size_t s1, const byte b2[], size_t s2)
  {
    ASSERT(b1);
    ASSERT(s1);
    ASSERT(b2);
    ASSERT(s2);

    // Will throw if ptr wraps. T* and size_t causing trouble on Linux
    SafeInt<size_t> si1((size_t)b1); si1 += s1;
    g_dummy = (void*)(size_t)si1;
    SafeInt<size_t> si2((size_t)b2); si2 += s2;
    g_dummy = (void*)(size_t)si2;

    // These early outs break the contract regarding timing.
    // https://code.google.com/p/owasp-esapi-cplusplus/issues/detail?id=5

    if ( b1 == b2 ) {
      return true;
    }
    if ( b1 == nullptr || b2 == nullptr ) {
      return (b1 == b2);
    }
    if ( s1 != s2 ) {
      return false;
    }
        
    int result = 0;
    // Make sure to go through ALL the bytes. We use the fact that if
    // you XOR any bit stream with itself the result will be all 0 bits,
    // which in turn yields 0 for the result.
    for(size_t i = 0; i < s2; i++) {
      // XOR the 2 current bytes and then OR with the outstanding result.
      result |= (b1[i] ^ b2[i]);
    }
    return (result == 0) ? true : false;
  }

} // NAMESPACE esapi
