/*
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

#include "EsapiCommon.h"
#include "crypto/KeyDerivationFunction.h"
#include "crypto/SecretKey.h"

#include "safeint/SafeInt3.hpp"

#include <sstream>
#include <algorithm>
#include <stdexcept>

#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>

/**
 * This class implements a Key Derivation Function (KDF) and supporting methods.
 * A KDF is a function with which an input key (called the Key Derivation Key,
 * or KDK) and other input data are used to securely generate (i.e., derive)
 * keying material that can be employed by cryptographic algorithms.
 * <p>
 * <b>Acknowledgments</b>:
 * ESAPI's KDF is patterned after suggestions first made by cryptographer
 * Dr. David A. Wagner and later extended to follow KDF in counter mode
 * as specified by section 5.1 of NIST SP 800-108. Jeffrey Walton and the NSA
 * also made valuable suggestions regarding the modeling of the method,
 * {@link #computeDerivedKey(SecretKey, int, String)}.
 *
 * @author kevin.w.wall@gmail.com
 * @author noloader@gmail.com
 * @since 2.0
 */

namespace esapi
{
  
  SecretKey KeyDerivationFunction::computeDerivedKey(const SecretKey& keyDerivationKey, unsigned int keySize, const std::string& purpose)
  {
    // We would choose a larger minimum key size, but we want to be
    // able to accept DES for legacy encryption needs.
    ASSERT( keyDerivationKey.SizeInBytes()  > 0 );
    ASSERT( keySize >= 56 );
    ASSERT( (keySize % 8) == 0 );
    ASSERT( !purpose.empty());
    ASSERT( purpose == "authenticity" || purpose == "encryption" );

    if(!(keySize >= 56))
      {
        std::ostringstream oss;
        oss << "KeyDerivationFunction: key has size of " << keySize << ", which is less than minimum of 56-bits.";
        throw std::invalid_argument(oss.str());
      }

    if(!((keySize % 8) == 0))
      {
        std::ostringstream oss;
        oss << "KeyDerivationFunction: key size (" << keySize << ") must be a even multiple of 8-bits.";
        throw std::invalid_argument(oss.str());
      }

    if(purpose.empty())
      {
        std::ostringstream oss;
        oss << "Purpose \'" << purpose << "\' is null, empty, or not valid. Purpose should be either \'authenticity\' or \'encryption\'.";
        throw std::invalid_argument(oss.str());
      }

    keySize = calcKeySize( keySize );
    ASSERT(keySize);

    /*
      byte[] derivedKey = new byte[ keySize ];
      byte[] label;              // Same purpose as NIST SP 800-108's "label" in section 5.1.
      byte[] context;            // See setContext() for details.
      try {
      label = purpose.getBytes("UTF-8");
      context = context_.getBytes("UTF-8");
      } catch (UnsupportedEncodingException e) {
      throw new EncryptionException("Encryption failure (internal encoding error: UTF-8)",
      "UTF-8 encoding is NOT supported as a standard byte encoding: " + e.getMessage(), e);
      }
    */

    // Consistency with Java implementation. This class needs to wire-up a context.
    const std::string& label = purpose;
    const std::string context;

    // Note that keyDerivationKey is going to be some SecretKey like an AES or
    // DESede key, but not an HmacSHA1 key. That means it is not likely
    // going to be 20 bytes but something different. Experiments show
    // that doesn't really matter though as the SecretKeySpec CTOR on
    // the following line still returns the appropriate sized key for
    // HmacSHA1. So, if keyDerivationKey was originally (say) a 56-bit
    // DES key, then there is apparently some key-stretching going on here
    // under the hood to create 'sk' so that it is 20 bytes. I cannot vouch
    // for how secure this key-stretching is. Worse, it might not be specified
    // as to *how* it is done and left to each JCE provider.

    /*
      SecretKey sk = new SecretKeySpec(keyDerivationKey.getEncoded(), "HmacSHA1");
      Mac mac = null;

      try {
      mac = Mac.getInstance("HmacSHA1");
      mac.init(sk);
      } catch( InvalidKeyException ex ) {
      logger.error(Logger.SECURITY_FAILURE, "Created HmacSHA1 Mac but SecretKey sk has alg " + sk.getAlgorithm(), ex);
      throw ex;
      }
    */
        
    /*
    // Repeatedly call of HmacSHA1 hash until we've collected enough bits
    // for the derived key. The first time through, we calculate the HmacSHA1
    // on the "purpose" string, but subsequent calculations are performed
    // on the previous result.
    int ctr = 1;    // Iteration counter for NIST 800-108
    int totalCopied = 0;
    int destPos = 0;
    int len = 0;
    byte[] tmpKey = null;  // Do not declare inside do-while loop!!!
    do {
    //
    // This is to make our KDF more along the line of NIST's.
    // NIST's Special Publication 800-108 performs the following in
    // the iterative loop of Section 5.1:
    //       n := number of blocks required to fulfill request
    //       for i = 1 to n, do
    //           K(i) := PRF(KDK, [i]2 || Label || 0x00 || Context || [L]2)
    //           result(i) := result(i-1) || K(i)
    //       end
    // where '||' is represents bit string concatenation, and PRF is
    // an NIST approved pseudo-random function (such as an HMAC),
    // KDK is the key derivation key, [i]2 is the big-endian binary
    // representation of the iteration, and [L]2 is the bits
    // requested by the caller, and 0x00 represents a null byte
    // used as a separation indicator.  However, other sections of this
    // document (Section 7.6) implies that Context is to be an
    // optional field (based on NIST's use of the word SHOULD
    // rather than MUST)

    mac.update( ByteConversionUtil.fromInt( ctr++ ) );
    mac.update(label);
    mac.update((byte) '\0');
    mac.update(context);    // This is problematic for us. See Jeff Walton's
    // analysis of ESAPI 2.0's KDF for details.
    // Maybe for 2.1, we'll see; 2.0 too close to GA.
          
    // According to the Javadoc for Mac.doFinal(byte[]),
    // "A call to this method resets this Mac object to the state it was
    // in when previously initialized via a call to init(Key) or
    // init(Key, AlgorithmParameterSpec). That is, the object is reset
    // and available to generate another MAC from the same key, if
    // desired, via new calls to update and doFinal." Therefore, we do
    // not do an explicit reset().
    tmpKey = mac.doFinal( ByteConversionUtil.fromInt( keySize ) );
          
    if ( tmpKey.length >= keySize ) {
    len = keySize;
    } else {
    len = Math.min(tmpKey.length, keySize - totalCopied);
    }

    System.arraycopy(tmpKey, 0, derivedKey, destPos, len);
    label = tmpKey;
    totalCopied += tmpKey.length;
    destPos += len;
    } while( totalCopied < keySize );
        
    // Don't leave remnants of the partial key in memory. (Note: we could
    // not do this if tmpKey were declared in the do-while loop.
    for ( int i = 0; i < tmpKey.length; i++ ) {
    tmpKey[i] = '\0';
    }
    tmpKey = null;  // Make it immediately eligible for GC.
    */

    // Returned to caller
    SecretKey derived(keySize);

    // Counter
    unsigned int ctr = 1;
    size_t idx = 0;

    while(keySize)
      {
        const unsigned int req = std::min((unsigned int)CryptoPP::SHA1::DIGESTSIZE, keySize);
        const byte i[4] = { (ctr >> 24 && 0xff), (ctr >> 16 && 0xff), (ctr >> 8 && 0xff), (ctr && 0xff) };
        const byte nil = '\0';

        CryptoPP::HMAC<CryptoPP::SHA1> hmac(keyDerivationKey.BytePtr(), keyDerivationKey.SizeInBytes());

        hmac.Update(i, sizeof(i));
        hmac.Update((const byte*)label.data(), label.size());
        hmac.Update(&nil, sizeof(nil));
        hmac.Update((const byte*)context.data(), context.size());

        // Though we continually call TruncatedFinal, we are retrieving a
        // full block except for possibly the last block
        hmac.TruncatedFinal(derived.BytePtr()+idx, req);

        idx += req;
        keySize -= req;        
      }

    // Convert it back into a SecretKey of the appropriate type.
    // return new SecretKeySpec(derivedKey, keyDerivationKey.getAlgorithm());

    return derived;
  }

  /**
   * Check if specified algorithm name is a valid PRF that can be used.
   * @param prfAlgName  Name of the PRF algorithm; e.g., "HmacSHA1", "HmacSHA384", etc.
   * @return  True if {@code prfAlgName} is supported, otherwise false.
   */

  /*
    public static boolean isValidPRF(String prfAlgName) {
    for (PRF_ALGORITHMS prf : PRF_ALGORITHMS.values()) {
    if ( prf.getAlgName().equals(prfAlgName) ) {
    return true;
    }
    }
    return false;
    }

    public static PRF_ALGORITHMS convertNameToPRF(String prfAlgName) {
    for (PRF_ALGORITHMS prf : PRF_ALGORITHMS.values()) {
    if ( prf.getAlgName().equals(prfAlgName) ) {
    return prf;
    }
    }
    throw new IllegalArgumentException("Algorithm name " + prfAlgName +
    " not a valid PRF algorithm name for the ESAPI KDF.");
    }
    
    public static PRF_ALGORITHMS convertIntToPRF(int selection) {
    for (PRF_ALGORITHMS prf : PRF_ALGORITHMS.values()) {
    if ( prf.getValue() == selection ) {
    return prf;
    }
    }
    throw new IllegalArgumentException("No KDF PRF algorithm found for value name " + selection);    
    }
  */

  /**
   * Calculate the size of a key.
   */
  unsigned int KeyDerivationFunction::calcKeySize(unsigned int keyBits)
  {
    ASSERT(keyBits >= 56);
    ASSERT(0 == keyBits % 8);

    SafeInt<unsigned int> k(keyBits);
    return (unsigned int)((k + 7) / 8);
  }

}; // NAMESPACE esapi
