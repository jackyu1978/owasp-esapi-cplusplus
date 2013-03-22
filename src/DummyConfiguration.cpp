/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 */

#include "EsapiCommon.h"
#include "DummyConfiguration.h"

namespace esapi
{
  NarrowString DummyConfiguration::getApplicationName()
  {
#if defined(ESAPI_OS_WINDOWS)
    CHAR name[MAX_PATH*2];
    DWORD size = COUNTOF(name);
    if((size = GetModuleFileNameA(NULL, name, size)) >= COUNTOF(name))
      return "Unknown";

    return NarrowString(name, size);
#endif

    return "Unknown";
  }
  String DummyConfiguration::getLogImplementation()
  {
    return "Unknown";
  }
  String DummyConfiguration::getAuthenticationImplementation()
  {
    return "SRP";
  }
  String DummyConfiguration::getEncoderImplementation()
  {
    return "Base64";
  }
  String DummyConfiguration::getAccessControlImplementation()
  {
    return "Unknown";
  }
  String DummyConfiguration::getIntrusionDetectionImplementation()
  {
    return "Unknown";
  }
  String DummyConfiguration::getRandomizerImplementation()
  {
    return "Unknown";
  }
  String DummyConfiguration::getEncryptionImplementation()
  {
    return "Unknown";
  }
  String DummyConfiguration::getValidationImplementation()
  {
    return "Unknown";
  }
  Pattern DummyConfiguration::getValidationPattern(const NarrowString &)
  {
    return "Unknown";
  }
  bool DummyConfiguration::getLenientDatesAccepted()
  {
    return "Unknown";
  }
  String DummyConfiguration::getExecutorImplementation()
  {
    return "Unknown";
  }
  String DummyConfiguration::getHTTPUtilitiesImplementation()
  {
    return "Unknown";
  }
  SecureByteArray DummyConfiguration::getMasterKey()
  {
    static const byte key[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    return SecureByteArray(key, COUNTOF(key));
  }
  String DummyConfiguration::getUploadDirectory()
  {
    return "Unknown";
  }
  String DummyConfiguration::getUploadTempDirectory()
  {
    return "Unknown";
  }
  int DummyConfiguration::getEncryptionKeyLength()
  {
    return 16;
  }
  SecureByteArray DummyConfiguration::getMasterSalt()
  {
    static const byte salt[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    return SecureByteArray(salt, COUNTOF(salt));
  }
  StringList DummyConfiguration::getAllowedExecutables()
  {
    return StringList();
  }
  StringList DummyConfiguration::getAllowedFileExtensions()
  {
    return StringList();
  }
  int DummyConfiguration::getAllowedFileUploadSize()
  {
    return 1024 * 1024;
  }
  String DummyConfiguration::getPasswordParameterName()
  {
    return "Unknown";
  }
  String DummyConfiguration::getUsernameParameterName()
  {
    return "Unknown";
  }
  String DummyConfiguration::getEncryptionAlgorithm()
  {
    return "AES/CBC";
  }
  String DummyConfiguration::getCipherTransformation()
  {
    return "AES/CBC/PKCS5";
  }
  String DummyConfiguration::setCipherTransformation(const NarrowString &)
  {
    return "AES/CBC";
  }
  String DummyConfiguration::getPreferredJCEProvider()
  {
    return "SunJCE";
  }
  bool DummyConfiguration::useMACforCipherText()
  {
    return true;
  }
  bool DummyConfiguration::overwritePlainText()
  {
    return true;
  }
  String DummyConfiguration::getIVType()
  {
    return "Unique";
  }
  SecureByteArray DummyConfiguration::getFixedIV()
  {
    static const byte iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    return SecureByteArray(iv, COUNTOF(iv));
  }

  const StringList& DummyConfiguration::getCombinedCipherModes()
  {
    MutexLock lock(getClassLock());

    static bool init = false;
    static StringList cipherModes;

    MEMORY_BARRIER();
    if(!init)
      {
        cipherModes.push_back("EAX");
        cipherModes.push_back("CCM");
        cipherModes.push_back("GCM");
        init = true;
      }

    MEMORY_BARRIER();
    return cipherModes;
  }

  const StringList& DummyConfiguration::getAdditionalAllowedCipherModes()
  {
    MutexLock lock(getClassLock());

    static bool init = false;
    static StringList cipherModes;

    MEMORY_BARRIER();
    if(!init)
      {
        cipherModes.push_back("CBC");
        cipherModes.push_back("CFB");
        cipherModes.push_back("OFB");
        init = true;
      }

    MEMORY_BARRIER();
    return cipherModes;
  }

  String DummyConfiguration::getHashAlgorithm()
  {
    return "SHA-256";
  }
  int DummyConfiguration::getHashIterations()
  {
    return 1024;
  }
  String DummyConfiguration::getKDFPseudoRandomFunction()
  {
    return "SHA-256";
  }
  String DummyConfiguration::getCharacterEncoding()
  {
    return "UTF-8";
  }
  bool DummyConfiguration::getAllowMultipleEncoding()
  {
    return false;
  }
  bool DummyConfiguration::getAllowMixedEncoding()
  {
    return false;
  }
  StringList DummyConfiguration::getDefaultCanonicalizationCodecs()
  {
    return StringList();
  }
  String DummyConfiguration::getDigitalSignatureAlgorithm()
  {
    return "DSA";
  }
  int DummyConfiguration::getDigitalSignatureKeyLength()
  {
    return 2048;
  }
  String DummyConfiguration::getRandomAlgorithm()
  {
    return "SHA-256";
  }
  int DummyConfiguration::getAllowedLoginAttempts()
  {
    return 5;
  }
  int DummyConfiguration::getMaxOldPasswordHashes()
  {
    return -1;
  }
  bool DummyConfiguration::getDisableIntrusionDetection()
  {
    return true;
  }
  Threshold DummyConfiguration::getQuota(const NarrowString &)
  {
    return Threshold("", 0, 0, StringList());
  }
  String DummyConfiguration::getResourceFile(const NarrowString &)
  {
    return "Unknown";
  }
  bool DummyConfiguration::getForceHttpOnlySession()
  {
    return true;
  }
  bool DummyConfiguration::getForceSecureSession()
  {
    return true;
  }
  bool DummyConfiguration::getForceHttpOnlyCookies()
  {
    return true;
  }
  bool DummyConfiguration::getForceSecureCookies()
  {
    return true;
  }
  int DummyConfiguration::getMaxHttpHeaderSize()
  {
    return 1024 * 6;
  }
  InputStream DummyConfiguration::getResourceStream(const NarrowString &)
  {
    return "Unknown";
  }
  void DummyConfiguration::setResourceDirectory(const NarrowString &)
  {
  }
  String DummyConfiguration::getResponseContentType()
  {
    return "Unknown";
  }
  String DummyConfiguration::getHttpSessionIdName()
  {
    return "Unknown";
  }
  long DummyConfiguration::getRememberTokenDuration()
  {
    return 3 * 60 * 1000 /*millisec*/;
  }
  int DummyConfiguration::getSessionIdleTimeoutLength()
  {
    return 3 * 60 * 1000 /*millisec*/;
  }
  int DummyConfiguration::getSessionAbsoluteTimeoutLength()
  {
    return 3 * 60 * 1000 /*millisec*/;
  }
  bool DummyConfiguration::getLogEncodingRequired()
  {
    return true;
  }
  String DummyConfiguration::getLogApplicationName()
  {
    return "Unknown";
  }
  String DummyConfiguration::getLogServerIP()
  {
    return "127.0.0.1";
  }
  int DummyConfiguration::getLogLevel()
  {
    return 3;
  }
  String DummyConfiguration::getLogFileName()
  {
    return "Unknown";
  }
  int DummyConfiguration::getMaxLogFileSize()
  {
    return 1024*1024;
  }
  String DummyConfiguration::getWorkingDirectory()
  {
    return "Unknown";
  }

  Mutex& DummyConfiguration::getClassLock()
  {
    static Mutex s_mutex;
    return s_mutex;
  }
}

