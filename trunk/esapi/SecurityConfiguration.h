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

#include <fstream>
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
	class SecurityConfiguration
	{
	public:
		virtual std::string getApplicationName(void) =0;
		virtual std::string getLogImplementation(void) =0;
		virtual std::string getAuthenticationImplementation(void) =0;
		virtual std::string getEncoderImplementation(void) =0;
		virtual std::string getAccessControlImplementation(void) =0;
		virtual std::string getIntrusionDetectionImplementation(void) =0;
		virtual std::string getRandomizerImplementation(void) =0;
		virtual std::string getEncryptionImplementation(void) =0;
		virtual std::string getValidationImplementation(void) =0;
		virtual Pattern getValidationPattern(const std::string &) =0;
		virtual bool getLenientDatesAccepted(void) =0;
		virtual std::string getExecutorImplementation(void) =0;
		virtual std::string getHTTPUtilitiesImplementation(void) =0;
		virtual byte *getMasterKey(void) =0;
		virtual fstream getUploadDirectory(void) =0;
		virtual fstream getUploadTempDirectory(void) =0;
		virtual int getEncryptionKeyLength(void) =0;
		virtual byte *getMasterSalt(void) =0;
		virtual std::list<std::string> getAllowedExecutables(void) =0;
		virtual std::list<std::string> getAllowedFileExtensions(void) =0;
		virtual int getAllowedFileUploadSize(void) =0;
		virtual std::string getPasswordParameterName(void) =0;
		virtual std::string getUsernameParameterName(void) =0;
		virtual std::string getEncryptionAlgorithm(void) =0;
		virtual std::string getCipherTransformation(void) =0;
		virtual std::string setCipherTransformation(const std::string &) =0;
		virtual std::string getPreferredJCEProvider(void) =0;
		virtual bool useMACforCipherText(void) =0;
		virtual bool overwritePlainText(void) =0;
		virtual std::string getIVType(void) =0;
		virtual std::string getFixedIV(void) =0;
		virtual std::list<std::string> getCombinedCipherModes(void) =0;
		virtual std::list<std::string> getAdditionalAllowedCipherModes(void) =0;
		virtual std::string getHashAlgorithm(void) =0;
		virtual std::string getHashIterations(void) =0;
		virtual std::string getKDFPseudoRandomFunction(void) =0;
		virtual std::string getCharacterEncoding(void) =0;
		virtual bool getAllowMultipleEncoding(void) =0;
		virtual bool getAllowMixedEncoding(void) =0;
		virtual std::list<std::string> getDefaultCanonicalizationCodecs(void) =0;
		virtual std::string getDigitalSignatureAlgorithm(void) =0;
		virtual int getDigitalSignatureKeyLength(void) =0;
		virtual std::string getRandomAlgorithm(void) =0;
		virtual int getAllowedLoginAttempts(void) =0;
		virtual int getMaxOldPasswordHashes(void) =0;
		virtual bool getDisableIntrusionDetection(void) =0;
		virtual Threshold getQuota(const std::string &) =0;
		virtual fstream getResourceFile(const std::string &) =0;
		virtual bool getForceHttpOnlySession(void) =0;
		virtual bool getForceSecureSession(void) =0;
		virtual std::string getRandomAlgorithm(void) =0;
		virtual bool getForceHttpOnlyCookies(void) =0;
		virtual bool getForceSecureCookies(void) =0;
		virtual int getMaxHttpHeaderSize(void) =0;
		virtual InputStream getResourceStream(const std::string &) =0;
		virtual void setResourceDirectory(const std::string &) =0;
		virtual std::string getResponseContentType(void) =0;
		virtual std::string getHttpSessionIdName(void) =0;
		virtual long getRememberTokenDuration(void) =0;
		virtual int getSessionIdleTimeoutLength(void) =0;
		virtual int getSessionAbsoluteTimeoutLength(void) =0;
		virtual bool getLogEncodingRequired(void) =0;
		virtual bool getLogApplicationName(void) =0;
		virtual bool getLogServerIP(void) =0;
		virtual int getLogLevel(void) =0;
		virtual std::string getLogFileName(void) =0;
		virtual int getMaxLogFileSize(void) =0;
		virtual fstream getWorkingDirectory(void) =0;

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
		std::string name = null;

		/** The count at which this threshold is triggered. */
		int count = 0;

		/**
		 * The time frame within which 'count' number of actions has to be detected in order to
		 * trigger this threshold.
		 */
		long interval = 0;

		/**
		 * The list of actions to take if the threshold is met. It is expected that this is a list of std::strings, but
		 * your implementation could have this be a list of any type of 'actions' you wish to define.
		 */
		std::list<std::string> actions = null;

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
			this.name = name;
			this.count = count;
			this.interval = interval;
			this.actions = actions;
		}
	};
};
