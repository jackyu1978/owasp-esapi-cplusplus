/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) for C++ project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright &copy; 2011 - The OWASP Foundation
 *
 * Derived from org.owasp.esapi.Encryptor class in ESAPI 2.0 for JavaEE.
 * 
 * The ESAPI is published by OWASP under the new BSD license. You should read
 * and accept the LICENSE before you use, modify, and/or redistribute this
 * software.
 * 
 * @author kevin.w.wall@gmail.com
 * @author Jeff Walton (noloader .at. gmail.com)
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) [Java version]
 * @author Chris Schmidt (chrisisbeef .at. gmail.com) [Java version]
 * 
 * @created 2011
 */

#pragma once

#include "EsapiCommon.h"
#include "crypto/SecretKey.h"
#include "crypto/CipherText.h"
#include "crypto/PlainText.h"
#include "errors/EncryptionException.h"
#include "errors/IntegrityException.h"

namespace esapi {   // Preferred over the longer org::owasp::esapi
                    // which likely be counter-productive, as it would
                    // cause most developers to either 1) not use ESAPI at all
                    // or 2) utilize "using namespace org::owasp::esapi;"
                    // which would just make name space collisions all the
                    // more likely, or 3) make up some awkward, most likely
                    // unreadable name space alias, as in:
                    //      namespace ooec = ::org::owasp::crypto
                    // I'm thinking 1 simple name space for ALL of ESAPI?
                    // Thoughts?

  // These still need to be defined. Also, excuse the (Java)doc referring
  // to String(byte[], "UTF-8"); I haven't had time to change it.


  /**
   * The Encryptor interface provides a set of methods for performing common
   * encryption, random number, and hashing operations. Implementations should
   * rely on a strong cryptographic implementation, such as Crypto++.
   * Implementors should take care to ensure that they initialize their
   * implementation with a strong "master key", and that they protect this secret
   * as much as possible.
   * <P>
   * The main property controlling the selection of the implementation class is
   * the property {@code ESAPI.Encryptor} in {@code ESAPI.properties}. Most
   * of the the other encryption related properties have property names that
   * start with the string "Encryptor.". These properties all you to do
   * things such as select the encryption algorithms, the key size, etc.
   * </P><P>
   * In addition, there are two important properties (initially delivered as
   * unset from the ESAPI download) named {@code Encryptor.MasterKey} and
   * {@code Encryptor.MasterSalt} that must be set before using ESAPI encryption.
   * There is a <i>bash</i>(1) shell script provided with the standard ESAPI
   * distribution called 'setMasterKey.sh' that will assist you in setting
   * these two properties. The * script is in
   * 'src/examples/scripts/setMasterKey.sh'.
   * </P><P>
   * Possible future enhancements (depending on feedback) are discussed in
   * section 4 of
   * <a href="http://owasp-esapi-java.googlecode.com/svn/trunk/documentation/esapi4java-core-2.0-crypto-design-goals.doc">
   * Design Goals in OWASP ESAPI Cryptography</a>.
   * 
   * @author kevin.w.wall@gmail.com
   * @since 1.0
   */
  class ESAPI_EXPORT Encryptor {

  public:
    /**
     * Returns a string representation of the hash of the provided plaintext and
     * salt. The salt helps to protect against a rainbow table attack by mixing
     * in some extra data with the plaintext. Some good choices for a salt might
     * be an account name or some other string that is known to the application
     * but not to an attacker. 
     * See <a href="http://www.matasano.com/log/958/enough-with-the-rainbow-tables-what-you-need-to-know-about-secure-password-schemes/">
     * this article</a> for more information about hashing as it pertains to password schemes.
     * 
     * @param plaintext
     *      the plaintext String to encrypt
     * @param salt
     *      the salt to add to the plaintext String before hashing
     * @param iterations
     *      the number of times to iterate the hash
     * 
     * @return 
     *      the encrypted hash of 'plaintext' stored as a String
     * 
     * @throws EncryptionException
     *      if the specified hash algorithm could not be found or another
     *      problem exists with the hashing of 'plaintext'
     */
    virtual String hash(const String& plaintext, const String& salt, unsigned int iterations = 4096) const = 0;

    /**
     * Encrypts the provided plaintext bytes using the cipher transformation
     * specified by the property <code>Encryptor.CipherTransformation</code>
     * and the <i>master encryption key</i> as specified by the property
     * {@code Encryptor.MasterKey} as defined in the
     * <code>ESAPI.properties</code> file.
     * 
     * @param plaintext The {@code PlainText} to be encrypted.
     * @return the {@code CipherText} object from which the raw
     *              ciphertext, the IV, the cipher transformation, and many
     *              other aspects about the encryption detail may be extracted.
     * @throws EncryptionException Thrown if something should go wrong
     *              such as the crypto provider cannot be found, the cipher
     *              algorithm, cipher mode, or padding scheme not being
     *              supported, specifying an unsupported key size, specifying
     *              an IV of incorrect length, etc.
     * @see #encrypt(SecretKey, PlainText)
     */
    virtual CipherText encrypt(const PlainText& plaintext) const = 0;


    /**
     * Encrypts the provided plaintext bytes using the cipher transformation
     * specified by the property <code>Encryptor.CipherTransformation</code>
     * as defined in the <code>ESAPI.properties</code> file and the
     * <i>specified secret key</i>.
     * </p><p>
     * This method is similar to {@link #encrypt(PlainText)} except that it
     * permits a specific {@code SecretKey} to be used for encryption.
     *
     * @param key      The {@code SecretKey} to use for encrypting the plaintext.
     * @param plaintext    The byte stream to be encrypted. Note if a
     *           {@code String} is to be encrypted, it should be converted
     *           using {@code "some string".getBytes("UTF-8")}.
     * @return the {@code CipherText} object from which the raw
     *             ciphertext, the IV, the cipher transformation, and many
     *             other aspects about the encryption detail may be extracted.
     * @throws EncryptionException Thrown if something should go wrong
     *             such as the crypto provider cannot be found, the cipher
     *             algorithm, cipher mode, or padding scheme not being
     *             supported, specifying an unsupported key size, specifying
     *             an IV of incorrect length, etc.
     * @see #encrypt(PlainText)
     */
    virtual CipherText encrypt(const SecretKey& key, const PlainText& plaintext) const = 0;

    /**
     * Decrypts the provided {@link CipherText} using the information from it
     * and the <i>master encryption key</i> as specified by the property
     * {@code Encryptor.MasterKey} as defined in the {@code ESAPI.properties}
     * file.
     * </p>
     * @param ciphertext The {@code CipherText} object to be decrypted.
     * @return The {@code PlainText} object resulting from decrypting
     *          the specified ciphertext. Note that it it is desired to
     *          convert the returned plaintext byte array to a String
     *          is should be done using
     *          {@code new String(byte[], "UTF-8");} rather than simply
     *          using {@code new String(byte[]);} which uses native
     *          encoding and may not be portable across hardware and/or OS
     *          platforms.
     * @throws EncryptionException  Thrown if something should go
     *          wrong such as the crypto provider cannot be found, the
     *          cipher algorithm, cipher mode, or padding scheme not being
     *          supported, specifying an unsupported key size, or incorrect
     *          encryption key was specified or a {@code PaddingException}
     *          occurs.
     * @see #decrypt(SecretKey, CipherText)
     */
    virtual PlainText decrypt(const CipherText& ciphertext) const = 0;

    /**
     * Decrypts the provided {@link CipherText} using the information from it
     * and the <i>specified secret key</i>.
     * </p><p>
     * This decrypt method is similar to {@link #decrypt(CipherText)} except that
     * it allows decrypting with a secret key other than the <i>master secret key</i>.
     * </p>
     * @param key       The {@code SecretKey} to use for encrypting
     *                  the plaintext.
     * @param ciphertext The {@code CipherText} object to be decrypted.
     * @return The {@code PlainText} object resulting from decrypting
     *          the specified ciphertext. Note that it it is desired to
     *          convert the returned plaintext byte array to a String
     *          is should be done using {@code new String(byte[], "UTF-8");}
     *          rather than simply using {@code new String(byte[]);}
     *          which uses native encoding and may not be portable across
     *          hardware and/or OS platforms.
     * @throws EncryptionException  Thrown if something should go wrong
     *          such as the crypto provider cannot be found, the cipher
     *          algorithm, cipher mode, or padding scheme not being
     *          supported, specifying an unsupported key size, or incorrect
     *          encryption key was specified or a {@code PaddingException}
     *          occurs.
     * @see #decrypt(CipherText)
     */
    virtual PlainText decrypt(const SecretKey& key, const CipherText& ciphertext) const = 0;

    /**
     * Create a digital signature for the provided data and return it in a
     * string.
     * <p>
     * <b>Limitations:</b> A new public/private key pair used for ESAPI 2.0 digital
     * signatures with this method and {@link #verifySignature(const String&, const String&)}
     * are dynamically created when the default reference implementation class,
     * {@link ref::DefaultEncryptor} is first created.
     * Because this key pair is not persisted nor is the public key shared,
     * this method and the corresponding {@link #verifySignature(const String&, const String&)}
     * can not be used with expected results across JVM instances. This limitation
     * will be addressed in ESAPI 2.1.
     * </p>
     * 
     * @param data
     *      the data to sign
     * 
     * @return  the digital signature stored as a String
     * 
     * @throws EncryptionException
     *      if the specified signature algorithm cannot be found
     */
    virtual String sign(const String& data) const = 0;

    /**
     * Verifies a digital signature (created with the sign method) and returns
     * the boolean result.
     * <p>
     * <b>Limitations:</b> A new public/private key pair used for ESAPI 2.0 digital
     * signatures with this method and {@link #sign(const String&)}
     * are dynamically created when the default reference implementation class,
     * {@link ref::DefaultEncryptor} is first created.
     * Because this key pair is not persisted nor is the public key shared,
     * this method and the corresponding {@link #sign(const String&)}
     * can not be used with expected results across JVM instances. This limitation
     * will be addressed in ESAPI 2.1.
     * </p>
     * @param signature
     *      the signature to verify against 'data'
     * @param data
     *      the data to verify against 'signature'
     * 
     * @return 
     *      true, if the signature is verified, false otherwise
     * 
     */
    virtual bool verifySignature(const String& signature, const String& data) const = 0;

    /**
     * Creates a seal that binds a set of data and includes an expiration timestamp.
     * 
     * @param data
     *      the data to seal
     * @param timestamp
     *      the absolute expiration date of the data, expressed as seconds since the epoch
     * 
     * @return 
     *      the seal
     * @throws IntegrityException
     * 
     */
    virtual String seal(const String& data, time_t timestamp) const = 0;

    /**
     * Unseals data (created with the seal method) and throws an exception
     * describing any of the various problems that could exist with a seal, such
     * as an invalid seal format, expired timestamp, or decryption error.
     * 
     * @param seal
     *      the sealed data
     * 
     * @return 
     *      the original (unsealed) data
     * 
     * @throws EncryptionException 
     *      if the unsealed data cannot be retrieved for any reason
     */
    virtual String unseal(const String& seal) const = 0;

    /**
     * Verifies a seal (created with the seal method) and throws an exception
     * describing any of the various problems that could exist with a seal, such
     * as an invalid seal format, expired timestamp, or data mismatch.
     * 
     * @param seal
     *      the seal to verify
     * 
     * @return 
     *      true, if the seal is valid.  False otherwise
     */
    virtual bool verifySeal(const String& seal) const = 0;

    /**
     * Gets an absolute timestamp representing an offset from the current time to be used by
     * other functions in the library.
     * 
     * @param offset 
     *      the offset to add to the current time
     * 
     * @return 
     *      the absolute timestamp
     */
    virtual time_t getRelativeTimeStamp( time_t offset ) const = 0;


    /**
     * Gets a timestamp representing the current date and time to be used by
     * other functions in the library.
     * 
     * @return 
     *      a timestamp representing the current time
     */
    virtual time_t getTimeStamp() const = 0;

  protected:
    /** Do nothing virtual DTOR. */
    virtual ~Encryptor() { }

  private:
    // Make sure compiler never generates this.
    Encryptor& operator=(const Encryptor& rhs);

  };   // End class

}   // End 'namespace esapi'
