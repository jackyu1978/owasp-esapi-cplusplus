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
 * @author Daniel Amodio, dan.amodio@aspectsecurity.com
 *
 */

#pragma once

#include "EsapiCommon.h"
#include "crypto/PlainText.h"
#include "crypto/CipherText.h"
#include "crypto/SecretKey.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"

/**
 * This class implements functionality similar to Java's CryptoHelper for consistency
 */
namespace esapi
{
  class ESAPI_EXPORT CryptoHelper
  {
  public:

    // TODO: Also consider supplying implementation of RFC 2898 / PKCS#5 PBKDF2
    //               in this file as well??? Maybe save for ESAPI 2.1 or 3.0.

    /**
     * Generate a random secret key appropriate to the specified cipher algorithm
     * and key size.
     * @param alg   The cipher algorithm or cipher transformation. (If the latter is
     *                              passed, the cipher algorithm is determined from it.) Cannot be
     *                              null or empty.
     * @param keySize       The key size, in bits.
     * @return      A random {@code SecretKey} is returned.
     * @throws EncryptionException Thrown if cannot create secret key conforming to
     *                              requested algorithm with requested size. Typically this is caused by
     *                              specifying an unavailable algorithm or invalid key size.
     */
    static SecretKey generateSecretKey(const String& alg, unsigned int keySize);

    /**
     * The method is ESAPI's Key Derivation Function (KDF) that computes a
     * derived key from the {@code keyDerivationKey} for either
     * encryption / decryption or for authentication.
     * <p>
     * <b>CAUTION:</b> If this algorithm for computing derived keys from the
     * key derivation key is <i>ever</i> changed, we risk breaking backward compatibility of being
     * able to decrypt data previously encrypted with earlier / different versions
     * of this method. Therefore, do not change this unless you are 100% certain that
     * what you are doing will NOT change either of the derived keys for
     * ANY "key derivation key" AT ALL!!!
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
     * @param keySize    The cipher's key size (in bits) for the {@code keyDerivationKey}.
     *                   Must have a minimum size of 56 bits and be an integral multiple of 8-bits.
     *                   <b>Note well:</b> The derived key will have the same size as this.
     * @param purpose    The purpose for the derived key. Must be either the
     *                   string "encryption" or "authenticity". Use "encryption" for
     *                   creating a derived key to use for confidentiality, and "authenticity"
     *                   for a derived key to use with a MAC to ensure message authenticity.
     * @return    The derived {@code SecretKey} to be used according
     *            to the specified purpose. Note that this serves the same purpose
     *            as "label" in section 5.1 of NIST SP 800-108.
     * @throws NoSuchAlgorithmException    The {@code keyDerivationKey} has an unsupported
     *                                     encryption algorithm or no current JCE provider supports
     *                                     "HmacSHA1".
     * @throws EncryptionException    If "UTF-8" is not supported as an encoding, then
     *                                this is thrown with the original {@code UnsupportedEncodingException}
     *                                as the cause. (NOTE: This should never happen as "UTF-8" is supposed to
     *                                be a common encoding supported by all Java implementations. Support
     *                                for it is usually in rt.jar.)
     * @throws     Yes.
     * @deprecated Use{@code KeyDerivationFunction} instead. This method will be removed as of
     *                         ESAPI release 2.1 so if you are using this, please change your code.
     */
    SecretKey computeDerivedKey(const SecretKey& keyDerivationKey, unsigned int keyBits, const String& purpose);

    /**
     * Return true if specified cipher mode is one of those specified in the
     * {@code ESAPI.properties} file that supports both confidentiality
     * <b>and</b> authenticity (i.e., a "combined cipher mode" as NIST refers
     * to it).
     * @param cipherMode    The specified cipher mode to be used for the encryption
     *                      or decryption operation.
     * @return    true if the specified cipher mode is in the comma-separated list
     *            of cipher modes supporting both confidentiality and authenticity;
     *            otherwise false.
     * @see org.owasp.esapi.SecurityConfiguration#getCombinedCipherModes()
     */
    static bool isCombinedCipherMode(const String& cipherMode);

    /**
     * Return true if specified cipher mode is one that may be used for
     * encryption / decryption operations via {@link org.owasp.esapi.Encryptor}.
     * @param cipherMode The specified cipher mode to be used for the encryption
     *                   or decryption operation.
     * @return true if the specified cipher mode is in the comma-separated list
     *         of cipher modes supporting both confidentiality and authenticity;
     *         otherwise false.
     * @see #isCombinedCipherMode(String)
     * @see org.owasp.esapi.SecurityConfiguration#getCombinedCipherModes()
     * @see org.owasp.esapi.SecurityConfiguration#getAdditionalAllowedCipherModes()
     */
    static bool isAllowedCipherMode(const String& cipherMode);

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
     * @param ct    The specified {@code CipherText} object to check to see if
     *              it requires a MAC.
     * @returns     True if a MAC is required, false if it is not required.
     */
    static bool isMACRequired(const CipherText& cipherText);

    /**
     * If a Message Authentication Code (MAC) is required for the specified
     * {@code CipherText} object, then attempt to validate the MAC that
     * should be embedded within the {@code CipherText} object by using a
     * derived key based on the specified {@code SecretKey}.
     *
     * @param sk    The {@code SecretKey} used to derived a key to check
     *              the authenticity via the MAC.
     * @param ct    The {@code CipherText} that we are checking for a
     *              valid MAC. 
     *
     * @return  True is returned if a MAC is required and it is valid as
     *          verified using a key derived from the specified
     *          {@code SecretKey} or a MAC is not required. False is returned
     *          otherwise.
     */
    static bool isCipherTextMACvalid(const SecretKey& secretKey, const CipherText& cipherText);

    /**
     * Overwrite a byte array with a specified byte. This is frequently done
     * to a plaintext byte array so the sensitive data is not lying around
     * exposed in memory.
     * @param bytes The byte array to be overwritten.
     * @param x The byte array {@code bytes} is overwritten with this byte.
     */
    static void overwrite(byte bytes[], size_t size, byte x);

    /**
     * Overwrite a byte array with the byte containing '*'. That is, call
     * <pre>
     *              overwrite(bytes, (byte)'*');
     * </pre>
     * @param bytes The byte array to be overwritten.
     */
    static void overwrite(byte bytes[], size_t size);

    /**
     * Same as {@code copyByteArray(src, dest, src.length)}.
     * @param      src      the source array.
     * @param      dest     the destination array.
     * @exception  IndexOutOfBoundsException  if copying would cause
     *               access of data outside array bounds.
     * @exception  NullPointerException if either <code>src</code> or
     *               <code>dest</code> is <code>null</code>.
     */
    static void copyByteArray(const byte src[], size_t srcSize, byte dest[], size_t destSize);

    // These provide for a bit more type safety when copying bytes around.
    /**
     * Same as {@code System.arraycopy(src, 0, dest, 0, length)}.
     * 
     * @param      src      the source array.
     * @param      dest     the destination array.
     * @param      length   the number of array elements to be copied.
     * @exception  IndexOutOfBoundsException  if copying would cause
     *               access of data outside array bounds.
     * @exception  NullPointerException if either <code>src</code> or
     *               <code>dest</code> is <code>null</code>.
     */
    static void copyByteArray(const byte src[], size_t srcSize, byte dest[], size_t destSize, size_t copySize);

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
    static bool arrayCompare(const byte b1[], size_t s1, const byte b2[], size_t s2);

  private:
    // static Logger logger;

  private:
    CryptoHelper() { /** No instantiation */ };
  };
} // NAMESPACE esapi
