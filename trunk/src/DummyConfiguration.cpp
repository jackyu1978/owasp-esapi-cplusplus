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
  std::string DummyConfiguration::getApplicationName()
  {
#if defined(ESAPI_OS_WINDOWS)
    WCHAR wname[MAX_PATH*2];
    DWORD size = COUNTOF(wname);
    if((size = GetModuleFileName(NULL, wname, size)) >= COUNTOF(wname))
      return "Unknown";

    CHAR name[MAX_PATH*2];
    size = WideCharToMultiByte(CP_UTF8, 0, wname, size, name, COUNTOF(name), NULL, NULL);
    if(size >= COUNTOF(name))
      return "Unknown";

    return std::string(name, size);
#endif

    return "Unknown";
  }
  std::string DummyConfiguration::getLogImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getAuthenticationImplementation()
  {
    return "SRP";
  }
  std::string DummyConfiguration::getEncoderImplementation()
  {
    return "Base64";
  }
  std::string DummyConfiguration::getAccessControlImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getIntrusionDetectionImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getRandomizerImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getEncryptionImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getValidationImplementation()
  {
    return "Unknown";
  }
  Pattern DummyConfiguration::getValidationPattern(const std::string &)
  {
    return "Unknown";
  }
  bool DummyConfiguration::getLenientDatesAccepted()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getExecutorImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getHTTPUtilitiesImplementation()
  {
    return "Unknown";
  }
  SecureByteArray DummyConfiguration::getMasterKey()
  {
    const byte key[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    return SecureByteArray(key, COUNTOF(key));
  }
  std::string DummyConfiguration::getUploadDirectory()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getUploadTempDirectory()
  {
    return "Unknown";
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
  std::string DummyConfiguration::getPasswordParameterName()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getUsernameParameterName()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getEncryptionAlgorithm()
  {
    return "AES/CBC";
  }
  std::string DummyConfiguration::getCipherTransformation()
  {
    return "AES/CBC/PKCS5";
  }
  std::string DummyConfiguration::setCipherTransformation(const std::string &)
  {
    return "AES/CBC";
  }
  std::string DummyConfiguration::getPreferredJCEProvider()
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
  std::string DummyConfiguration::getIVType()
  {
    return "Unique";
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

  std::string DummyConfiguration::getHashAlgorithm()
  {
    return "SHA-256";
  }
  int DummyConfiguration::getHashIterations()
  {
    return 1024;
  }
  std::string DummyConfiguration::getKDFPseudoRandomFunction()
  {
    return "SHA-256";
  }
  std::string DummyConfiguration::getCharacterEncoding()
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
  std::string DummyConfiguration::getDigitalSignatureAlgorithm()
  {
    return "DSA";
  }
  int DummyConfiguration::getDigitalSignatureKeyLength()
  {
    return 2048;
  }
  std::string DummyConfiguration::getRandomAlgorithm()
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
  Threshold DummyConfiguration::getQuota(const std::string &)
  {
    return Threshold("", 0, 0, StringList());
  }
  std::string DummyConfiguration::getResourceFile(const std::string &)
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
  InputStream DummyConfiguration::getResourceStream(const std::string &)
  {
    return "Unknown";
  }
  void DummyConfiguration::setResourceDirectory(const std::string &)
  {
  }
  std::string DummyConfiguration::getResponseContentType()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getHttpSessionIdName()
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
  std::string DummyConfiguration::getLogApplicationName()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getLogServerIP()
  {
    return "127.0.0.1";
  }
  int DummyConfiguration::getLogLevel()
  {
    return 3;
  }
  std::string DummyConfiguration::getLogFileName()
  {
    return "Unknown";
  }
  int DummyConfiguration::getMaxLogFileSize()
  {
    return 1024*1024;
  }
  std::string DummyConfiguration::getWorkingDirectory()
  {
    return "Unknown";
  }

  Mutex& DummyConfiguration::getClassLock()
  {
    static Mutex s_mutex;
    return s_mutex;
  }
}