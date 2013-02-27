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

#include <set>
#include <string>

namespace esapi
{
/**
 * The {@code EncryptedProperties} interface represents a properties file
 * where all the data is encrypted before it is added, and decrypted when it
 * retrieved. This interface can be implemented in a number of ways, the
 * simplest being extending {@link java.util.Properties} and overloading
 * the {@code getProperty} and {@code setProperty} methods. In all cases,
 * the master encryption key, as given by the {@code Encryptor.MasterKey}
 * property in <b><code>ESAPI.properties</code></b> file.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author David Anderson (david.anderson@aspectsecurity.com)
 * @since June 1, 2007
 */
	class EncryptedProperties
	{
	public:
		virtual String getProperty(const String &) =0 throw EncryptionException;
		virtual String setProperty(const String &, const String &) =0 throw EncryptionException;
		virtual std::set<String> keySet() =0;
		virtual void load(InputStream) =0 throw IOException;
		virtual void store(OutputStream, const String &) =0 throw IOException;

		virtual ~EncryptedProperties() {};
	};
} // NAMESPACE

