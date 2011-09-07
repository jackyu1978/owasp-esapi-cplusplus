
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
      return "Unknown";;

    CHAR name[MAX_PATH*2];
    size = WideCharToMultiByte(CP_UTF8, 0, wname, size, name, COUNTOF(name), NULL, NULL);
    if(size >= COUNTOF(name))
      return "Unknown";;

    return std::string(name, size);
#endif

    return "Unknown";;
  }
  std::string DummyConfiguration::getLogImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getAuthenticationImplementation()
  {
    return "Unknown";
  }
  std::string DummyConfiguration::getEncoderImplementation()
  {
    return "Unknown";
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
    const byte iv[16] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
      0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };

    return SecureByteArray(iv, COUNTOF(iv));
  }
  std::list<std::string> DummyConfiguration::getAllowedExecutables()
  {
    return std::list<std::string>();
  }
  std::list<std::string> DummyConfiguration::getAllowedFileExtensions()
  {
    return std::list<std::string>();
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
    return "AES/CBC";
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
    return "Unpredictable";
  }
  std::string DummyConfiguration::getFixedIV()
  {
    return "00000000000000000000000000000000";
  }
  std::list<std::string> DummyConfiguration::getCombinedCipherModes()
  {
    return std::list<std::string>();
  }
  std::list<std::string> DummyConfiguration::getAdditionalAllowedCipherModes()
  {
    return std::list<std::string>();
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
  std::list<std::string> DummyConfiguration::getDefaultCanonicalizationCodecs()
  {
    return std::list<std::string>();
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
  int getMaxOldPasswordHashes()
  {
    return -1;
  }
  bool DummyConfiguration::getDisableIntrusionDetection()
  {
    return true;
  }
  Threshold DummyConfiguration::getQuota(const std::string &)
  {
    return Threshold("", 0, 0, std::list<std::string>());
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
}