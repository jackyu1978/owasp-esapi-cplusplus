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

#include <string>
#include <cstdio>

#include "crypto/PlainText.h"
#include "crypto/CipherText.h"
#include "crypto/SecretKey.h"

#include "errors/EncryptionException.h"
#include "errors/IntegrityException.h"

namespace esapi
{
/**
 * Reference implementation of the {@code Encryptor} interface. This implementation
 * layers on the Crypto++ provided cryptographic package. Algorithms used are
 * configurable in the {@code ESAPI.properties} file. The main property
 * controlling the selection of this class is {@code ESAPI.Encryptor}. Most of
 * the other encryption related properties have property names that start with
 * the string "Encryptor.".
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author kevin.w.wall@gmail.com
 * @author Chris Schmidt (chrisisbeef .at. gmail.com)
 * @since June 1, 2007; some methods since ESAPI Java 2.0
 * @see org.owasp.esapi.Encryptor
 */
	class Encryptor
	{
	public:
		virtual std::string hash(const std::string &, const std::string &) throw (EncryptionException) =0;
		virtual std::string hash(const std::string &, const std::string &, int) throw (EncryptionException) =0;
		virtual CipherText encrypt(PlainText) throw (EncryptionException) =0;
		virtual CipherText encrypt(SecretKey, PlainText) throw (EncryptionException) =0;
		virtual PlainText decrypt(CipherText) throw (EncryptionException) =0;
		virtual PlainText decrypt(SecretKey, CipherText) throw (EncryptionException) =0;
		virtual std::string sign(const std::string & data) throw (EncryptionException) =0;
		virtual bool verifySignature(const std::string &, const std::string &) =0;
		virtual std::string seal(const std::string &, long) throw (IntegrityException) =0;
		virtual std::string unseal(const std::string &) throw (EncryptionException) =0;
		virtual bool verifyseal(const std::string &) =0;
		virtual long getRelativeTimeStamp(long) =0;
		virtual long getTimeStamp() =0;

		virtual ~Encryptor() {};
	};
};
