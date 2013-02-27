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
    virtual String getApplicationName();
    virtual String getLogImplementation();
    virtual String getAuthenticationImplementation();
    virtual String getEncoderImplementation();
    virtual String getAccessControlImplementation();
    virtual String getIntrusionDetectionImplementation();
    virtual String getRandomizerImplementation();
    virtual String getEncryptionImplementation();
    virtual String getValidationImplementation();
    virtual Pattern getValidationPattern(const String &);
    virtual bool getLenientDatesAccepted();
    virtual String getExecutorImplementation();
    virtual String getHTTPUtilitiesImplementation();
    virtual SecureByteArray getMasterKey();
    virtual String getUploadDirectory();
    virtual String getUploadTempDirectory();
    virtual int getEncryptionKeyLength();
    virtual SecureByteArray getMasterSalt();
    virtual StringList getAllowedExecutables();
    virtual StringList getAllowedFileExtensions();
    virtual int getAllowedFileUploadSize();
    virtual String getPasswordParameterName();
    virtual String getUsernameParameterName();
    virtual String getEncryptionAlgorithm();
    virtual String getCipherTransformation();
    virtual String setCipherTransformation(const String &);
    virtual String getPreferredJCEProvider();
    virtual bool useMACforCipherText();
    virtual bool overwritePlainText();
    virtual String getIVType();
    virtual SecureByteArray getFixedIV();
    virtual const StringList& getCombinedCipherModes();
    virtual const StringList& getAdditionalAllowedCipherModes();
    virtual String getHashAlgorithm();
    virtual int getHashIterations();
    virtual String getKDFPseudoRandomFunction();
    virtual String getCharacterEncoding();
    virtual bool getAllowMultipleEncoding();
    virtual bool getAllowMixedEncoding();
    virtual StringList getDefaultCanonicalizationCodecs();
    virtual String getDigitalSignatureAlgorithm();
    virtual int getDigitalSignatureKeyLength();
    virtual String getRandomAlgorithm();
    virtual int getAllowedLoginAttempts();
    virtual int getMaxOldPasswordHashes();
    virtual bool getDisableIntrusionDetection();
    virtual Threshold getQuota(const String &);
    virtual String getResourceFile(const String &);
    virtual bool getForceHttpOnlySession();
    virtual bool getForceSecureSession();
    virtual bool getForceHttpOnlyCookies();
    virtual bool getForceSecureCookies();
    virtual int getMaxHttpHeaderSize();
    virtual InputStream getResourceStream(const String &);
    virtual void setResourceDirectory(const String &);
    virtual String getResponseContentType();
    virtual String getHttpSessionIdName();
    virtual long getRememberTokenDuration();
    virtual int getSessionIdleTimeoutLength();
    virtual int getSessionAbsoluteTimeoutLength();
    virtual bool getLogEncodingRequired();
    virtual String getLogApplicationName();
    virtual String getLogServerIP();
    virtual int getLogLevel();
    virtual String getLogFileName();
    virtual int getMaxLogFileSize();
    virtual String getWorkingDirectory();

    virtual ~DummyConfiguration() {};

  private:
    static Mutex& getClassLock();
  };
} // NAMESPACE



