/**
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*/

#pragma once

#include "util/SecureArray.h"

#include <string>
#include <list>
#include <string>

namespace esapi
{
  /**
  * The {@code SecurityConfiguration} interface stores all configuration information
  * that directs the behavior of the ESAPI implementation.
  * <br><br>
  * Protection of this configuration information is critical to the secure
  * operation of the application using the ESAPI. You should use operating system
  * access controls to limit access to wherever the configuration information is
  * stored.
  * <br><br>
  * Please note that adding another layer of encryption does not make the
  * attackers job much more difficult. Somewhere there must be a master "secret"
  * that is stored unencrypted on the application platform (unless you are
  * willing to prompt for some passphrase when you application starts or insert
  * a USB thumb drive or an HSM card, etc., in which case this master "secret"
  * it would only be in memory). Creating another layer of indirection provides
  * additional obfuscation, but doesn't provide any real additional security.
  * It's up to the reference implementation to decide whether this file should
  * be encrypted or not.
  * <br><br>
  * The ESAPI reference implementation (DefaultSecurityConfiguration.java) does
  * <i>not</i> encrypt its properties file.
  *
  * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
  *         href="http://www.aspectsecurity.com">Aspect Security</a>
  * @author David Anderson (david.anderson@aspectsecurity.com)
  * @since June 1, 2007
  */

  // Forawrd declaration
  class Threshold;

  typedef String Pattern;
  typedef String InputStream;

  class SecurityConfiguration
  {
  public:
    virtual String getApplicationName() =0;
    virtual String getLogImplementation() =0;
    virtual String getAuthenticationImplementation() =0;
    virtual String getEncoderImplementation() =0;
    virtual String getAccessControlImplementation() =0;
    virtual String getIntrusionDetectionImplementation() =0;
    virtual String getRandomizerImplementation() =0;
    virtual String getEncryptionImplementation() =0;
    virtual String getValidationImplementation() =0;
    virtual Pattern getValidationPattern(const NarrowString &) =0;
    virtual bool getLenientDatesAccepted() =0;
    virtual String getExecutorImplementation() =0;
    virtual String getHTTPUtilitiesImplementation() =0;
    virtual SecureByteArray getMasterKey() =0;
    virtual String getUploadDirectory() =0;
    virtual String getUploadTempDirectory() =0;
    virtual int getEncryptionKeyLength() =0;
    virtual SecureByteArray getMasterSalt() =0;
    virtual StringList getAllowedExecutables() =0;
    virtual StringList getAllowedFileExtensions() =0;
    virtual int getAllowedFileUploadSize() =0;
    virtual String getPasswordParameterName() =0;
    virtual String getUsernameParameterName() =0;
    virtual String getEncryptionAlgorithm() =0;
    virtual String getCipherTransformation() =0;
    virtual String setCipherTransformation(const NarrowString &) =0;
    virtual String getPreferredJCEProvider() =0;
    virtual bool useMACforCipherText() =0;
    virtual bool overwritePlainText() =0;
    virtual String getIVType() =0;
    virtual SecureByteArray getFixedIV() =0;
    virtual const StringList& getCombinedCipherModes() =0;
    virtual const StringList& getAdditionalAllowedCipherModes() =0;
    virtual String getHashAlgorithm() =0;
    virtual int getHashIterations() =0;
    virtual String getKDFPseudoRandomFunction() =0;
    virtual String getCharacterEncoding() =0;
    virtual bool getAllowMultipleEncoding() =0;
    virtual bool getAllowMixedEncoding() =0;
    virtual StringList getDefaultCanonicalizationCodecs() =0;
    virtual String getDigitalSignatureAlgorithm() =0;
    virtual int getDigitalSignatureKeyLength() =0;
    virtual String getRandomAlgorithm() =0;
    virtual int getAllowedLoginAttempts() =0;
    virtual int getMaxOldPasswordHashes() =0;
    virtual bool getDisableIntrusionDetection() =0;
    virtual Threshold getQuota(const NarrowString &) =0;
    virtual String getResourceFile(const NarrowString &) =0;
    virtual bool getForceHttpOnlySession() =0;
    virtual bool getForceSecureSession() =0;
    virtual bool getForceHttpOnlyCookies() =0;
    virtual bool getForceSecureCookies() =0;
    virtual int getMaxHttpHeaderSize() =0;
    virtual InputStream getResourceStream(const NarrowString &) =0;
    virtual void setResourceDirectory(const NarrowString &) =0;
    virtual String getResponseContentType() =0;
    virtual String getHttpSessionIdName() =0;
    virtual long getRememberTokenDuration() =0;
    virtual int getSessionIdleTimeoutLength() =0;
    virtual int getSessionAbsoluteTimeoutLength() =0;
    virtual bool getLogEncodingRequired() =0;
    virtual String getLogApplicationName() =0;
    virtual String getLogServerIP() =0;
    virtual int getLogLevel() =0;
    virtual String getLogFileName() =0;
    virtual int getMaxLogFileSize() =0;
    virtual String getWorkingDirectory() =0;

    virtual ~SecurityConfiguration() {};
  };

  /**
  * Models a simple threshold as a count and an interval, along with a set of actions to take if
  * the threshold is exceeded. These thresholds are used to define when the accumulation of a particular event
  * has met a set number within the specified time period. Once a threshold value has been met, various
  * actions can be taken at that point.
  */
  class Threshold
  {
  public:
    /** The name of this threshold. */
    String name;

    /** The count at which this threshold is triggered. */
    int count;

    /**
    * The time frame within which 'count' number of actions has to be detected in order to
    * trigger this threshold.
    */
    long interval;

    /**
    * The list of actions to take if the threshold is met. It is expected that this is a list of Strings, but
    * your implementation could have this be a list of any type of 'actions' you wish to define.
    */
    StringList actions;

    /**
    * Constructs a threshold that is composed of its name, its threshold count, the time window for
    * the threshold, and the actions to take if the threshold is triggered.
    *
    * @param name The name of this threshold.
    * @param count The count at which this threshold is triggered.
    * @param interval The time frame within which 'count' number of actions has to be detected in order to
    * trigger this threshold.
    * @param actions The list of actions to take if the threshold is met.
    */
    Threshold(const NarrowString & name, int count, long interval, StringList actions)
    {
      this->name = name;
      this->count = count;
      this->interval = interval;
      this->actions = actions;
    }
  };
} // NAMESPACE

