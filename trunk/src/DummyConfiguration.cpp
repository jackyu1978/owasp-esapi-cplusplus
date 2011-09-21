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
  String DummyConfiguration::getApplicationName()
  {
#if defined(ESAPI_OS_WINDOWS)
    WCHAR wname[MAX_PATH*2];
    DWORD size = COUNTOF(wname);
    if((size = GetModuleFileName(NULL, wname, size)) >= COUNTOF(wname))
      return L"Unknown";

    return String(wname, size);
#endif

    return L"Unknown";
  }
  String DummyConfiguration::getLogImplementation()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getAuthenticationImplementation()
  {
    return L"SRP";
  }
  String DummyConfiguration::getEncoderImplementation()
  {
    return L"Base64";
  }
  String DummyConfiguration::getAccessControlImplementation()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getIntrusionDetectionImplementation()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getRandomizerImplementation()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getEncryptionImplementation()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getValidationImplementation()
  {
    return L"Unknown";
  }
  Pattern DummyConfiguration::getValidationPattern(const String &)
  {
    return L"Unknown";
  }
  bool DummyConfiguration::getLenientDatesAccepted()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getExecutorImplementation()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getHTTPUtilitiesImplementation()
  {
    return L"Unknown";
  }
  SecureByteArray DummyConfiguration::getMasterKey()
  {
    const byte key[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    return SecureByteArray(key, COUNTOF(key));
  }
  String DummyConfiguration::getUploadDirectory()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getUploadTempDirectory()
  {
    return L"Unknown";
  }
  int DummyConfiguration::getEncryptionKeyLength()
  {
    return 16;
  }
  SecureByteArray DummyConfiguration::getMasterSalt()
  {
    const byte salt[16] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };

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
    return L"Unknown";
  }
  String DummyConfiguration::getUsernameParameterName()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getEncryptionAlgorithm()
  {
    return L"AES/CBC";
  }
  String DummyConfiguration::getCipherTransformation()
  {
    return L"AES/CBC/PKCS5";
  }
  String DummyConfiguration::setCipherTransformation(const String &)
  {
    return L"AES/CBC";
  }
  String DummyConfiguration::getPreferredJCEProvider()
  {
    return L"SunJCE";
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
    return L"Unique";
  }
  SecureByteArray DummyConfiguration::getFixedIV()
  {
    const byte iv[16] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
                          0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };

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
        cipherModes.push_back(L"EAX");
        cipherModes.push_back(L"CCM");
        cipherModes.push_back(L"GCM");
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
        cipherModes.push_back(L"CBC");
        cipherModes.push_back(L"CFB");
        cipherModes.push_back(L"OFB");
        init = true;
      }

    MEMORY_BARRIER();
    return cipherModes;
  }

  String DummyConfiguration::getHashAlgorithm()
  {
    return L"SHA-256";
  }
  int DummyConfiguration::getHashIterations()
  {
    return 1024;
  }
  String DummyConfiguration::getKDFPseudoRandomFunction()
  {
    return L"SHA-256";
  }
  String DummyConfiguration::getCharacterEncoding()
  {
    return L"UTF-8";
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
    return L"DSA";
  }
  int DummyConfiguration::getDigitalSignatureKeyLength()
  {
    return 2048;
  }
  String DummyConfiguration::getRandomAlgorithm()
  {
    return L"SHA-256";
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
  Threshold DummyConfiguration::getQuota(const String &)
  {
    return Threshold(L"", 0, 0, StringList());
  }
  String DummyConfiguration::getResourceFile(const String &)
  {
    return L"Unknown";
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
  InputStream DummyConfiguration::getResourceStream(const String &)
  {
    return L"Unknown";
  }
  void DummyConfiguration::setResourceDirectory(const String &)
  {
  }
  String DummyConfiguration::getResponseContentType()
  {
    return L"Unknown";
  }
  String DummyConfiguration::getHttpSessionIdName()
  {
    return L"Unknown";
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
    return L"Unknown";
  }
  String DummyConfiguration::getLogServerIP()
  {
    return L"127.0.0.1";
  }
  int DummyConfiguration::getLogLevel()
  {
    return 3;
  }
  String DummyConfiguration::getLogFileName()
  {
    return L"Unknown";
  }
  int DummyConfiguration::getMaxLogFileSize()
  {
    return 1024*1024;
  }
  String DummyConfiguration::getWorkingDirectory()
  {
    return L"Unknown";
  }

  Mutex& DummyConfiguration::getClassLock()
  {
    static Mutex s_mutex;
    return s_mutex;
  }
}

