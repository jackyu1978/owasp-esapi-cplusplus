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

#include "SecurityConfiguration.h"
#include "util/Mutex.h"

namespace esapi
{
  class DummyConfiguration : public SecurityConfiguration
  {
  public:
    virtual std::string getApplicationName();
    virtual std::string getLogImplementation();
    virtual std::string getAuthenticationImplementation();
    virtual std::string getEncoderImplementation();
    virtual std::string getAccessControlImplementation();
    virtual std::string getIntrusionDetectionImplementation();
    virtual std::string getRandomizerImplementation();
    virtual std::string getEncryptionImplementation();
    virtual std::string getValidationImplementation();
    virtual Pattern getValidationPattern(const std::string &);
    virtual bool getLenientDatesAccepted();
    virtual std::string getExecutorImplementation();
    virtual std::string getHTTPUtilitiesImplementation();
    virtual SecureByteArray getMasterKey();
    virtual std::string getUploadDirectory();
    virtual std::string getUploadTempDirectory();
    virtual int getEncryptionKeyLength();
    virtual SecureByteArray getMasterSalt();
    virtual StringList getAllowedExecutables();
    virtual StringList getAllowedFileExtensions();
    virtual int getAllowedFileUploadSize();
    virtual std::string getPasswordParameterName();
    virtual std::string getUsernameParameterName();
    virtual std::string getEncryptionAlgorithm();
    virtual std::string getCipherTransformation();
    virtual std::string setCipherTransformation(const std::string &);
    virtual std::string getPreferredJCEProvider();
    virtual bool useMACforCipherText();
    virtual bool overwritePlainText();
    virtual std::string getIVType();
    virtual SecureByteArray getFixedIV();
    virtual const StringList& getCombinedCipherModes();
    virtual const StringList& getAdditionalAllowedCipherModes();
    virtual std::string getHashAlgorithm();
    virtual int getHashIterations();
    virtual std::string getKDFPseudoRandomFunction();
    virtual std::string getCharacterEncoding();
    virtual bool getAllowMultipleEncoding();
    virtual bool getAllowMixedEncoding();
    virtual StringList getDefaultCanonicalizationCodecs();
    virtual std::string getDigitalSignatureAlgorithm();
    virtual int getDigitalSignatureKeyLength();
    virtual std::string getRandomAlgorithm();
    virtual int getAllowedLoginAttempts();
    virtual int getMaxOldPasswordHashes();
    virtual bool getDisableIntrusionDetection();
    virtual Threshold getQuota(const std::string &);
    virtual std::string getResourceFile(const std::string &);
    virtual bool getForceHttpOnlySession();
    virtual bool getForceSecureSession();
    virtual bool getForceHttpOnlyCookies();
    virtual bool getForceSecureCookies();
    virtual int getMaxHttpHeaderSize();
    virtual InputStream getResourceStream(const std::string &);
    virtual void setResourceDirectory(const std::string &);
    virtual std::string getResponseContentType();
    virtual std::string getHttpSessionIdName();
    virtual long getRememberTokenDuration();
    virtual int getSessionIdleTimeoutLength();
    virtual int getSessionAbsoluteTimeoutLength();
    virtual bool getLogEncodingRequired();
    virtual std::string getLogApplicationName();
    virtual std::string getLogServerIP();
    virtual int getLogLevel();
    virtual std::string getLogFileName();
    virtual int getMaxLogFileSize();
    virtual std::string getWorkingDirectory();

    virtual ~DummyConfiguration() {};

  private:
    static Mutex& getClassLock();
  };
};
