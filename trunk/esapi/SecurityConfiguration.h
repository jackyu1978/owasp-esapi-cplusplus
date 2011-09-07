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

  typedef std::string Pattern;
  typedef std::string InputStream;

  class SecurityConfiguration
  {
  public:
    virtual std::string getApplicationName() =0;
    virtual std::string getLogImplementation() =0;
    virtual std::string getAuthenticationImplementation() =0;
    virtual std::string getEncoderImplementation() =0;
    virtual std::string getAccessControlImplementation() =0;
    virtual std::string getIntrusionDetectionImplementation() =0;
    virtual std::string getRandomizerImplementation() =0;
    virtual std::string getEncryptionImplementation() =0;
    virtual std::string getValidationImplementation() =0;
    virtual Pattern getValidationPattern(const std::string &) =0;
    virtual bool getLenientDatesAccepted() =0;
    virtual std::string getExecutorImplementation() =0;
    virtual std::string getHTTPUtilitiesImplementation() =0;
    virtual SecureByteArray getMasterKey() =0;
    virtual std::string getUploadDirectory() =0;
    virtual std::string getUploadTempDirectory() =0;
    virtual int getEncryptionKeyLength() =0;
    virtual SecureByteArray getMasterSalt() =0;
    virtual std::list<std::string> getAllowedExecutables() =0;
    virtual std::list<std::string> getAllowedFileExtensions() =0;
    virtual int getAllowedFileUploadSize() =0;
    virtual std::string getPasswordParameterName() =0;
    virtual std::string getUsernameParameterName() =0;
    virtual std::string getEncryptionAlgorithm() =0;
    virtual std::string getCipherTransformation() =0;
    virtual std::string setCipherTransformation(const std::string &) =0;
    virtual std::string getPreferredJCEProvider() =0;
    virtual bool useMACforCipherText() =0;
    virtual bool overwritePlainText() =0;
    virtual std::string getIVType() =0;
    virtual std::string getFixedIV() =0;
    virtual std::list<std::string> getCombinedCipherModes() =0;
    virtual std::list<std::string> getAdditionalAllowedCipherModes() =0;
    virtual std::string getHashAlgorithm() =0;
    virtual int getHashIterations() =0;
    virtual std::string getKDFPseudoRandomFunction() =0;
    virtual std::string getCharacterEncoding() =0;
    virtual bool getAllowMultipleEncoding() =0;
    virtual bool getAllowMixedEncoding() =0;
    virtual std::list<std::string> getDefaultCanonicalizationCodecs() =0;
    virtual std::string getDigitalSignatureAlgorithm() =0;
    virtual int getDigitalSignatureKeyLength() =0;
    virtual std::string getRandomAlgorithm() =0;
    virtual int getAllowedLoginAttempts() =0;
    virtual int getMaxOldPasswordHashes() =0;
    virtual bool getDisableIntrusionDetection() =0;
    virtual Threshold getQuota(const std::string &) =0;
    virtual std::string getResourceFile(const std::string &) =0;
    virtual bool getForceHttpOnlySession() =0;
    virtual bool getForceSecureSession() =0;
    virtual bool getForceHttpOnlyCookies() =0;
    virtual bool getForceSecureCookies() =0;
    virtual int getMaxHttpHeaderSize() =0;
    virtual InputStream getResourceStream(const std::string &) =0;
    virtual void setResourceDirectory(const std::string &) =0;
    virtual std::string getResponseContentType() =0;
    virtual std::string getHttpSessionIdName() =0;
    virtual long getRememberTokenDuration() =0;
    virtual int getSessionIdleTimeoutLength() =0;
    virtual int getSessionAbsoluteTimeoutLength() =0;
    virtual bool getLogEncodingRequired() =0;
    virtual std::string getLogApplicationName() =0;
    virtual std::string getLogServerIP() =0;
    virtual int getLogLevel() =0;
    virtual std::string getLogFileName() =0;
    virtual int getMaxLogFileSize() =0;
    virtual std::string getWorkingDirectory() =0;

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
    std::string name;

    /** The count at which this threshold is triggered. */
    int count;

    /**
    * The time frame within which 'count' number of actions has to be detected in order to
    * trigger this threshold.
    */
    long interval;

    /**
    * The list of actions to take if the threshold is met. It is expected that this is a list of std::strings, but
    * your implementation could have this be a list of any type of 'actions' you wish to define.
    */
    std::list<std::string> actions;

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
    Threshold(const std::string & name, int count, long interval, std::list<std::string> actions)
    {
      this->name = name;
      this->count = count;
      this->interval = interval;
      this->actions = actions;
    }
  };
};
