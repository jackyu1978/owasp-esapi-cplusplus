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
		virtual String hash(const String &, const String &, unsigned int) =0;
		virtual CipherText encrypt(const PlainText&) =0;
		virtual CipherText encrypt(const SecretKey&, const PlainText&) =0;
		virtual PlainText decrypt(const CipherText&) =0;
		virtual PlainText decrypt(const SecretKey&, const CipherText&) =0;
		virtual String sign(const String & data) =0;
		virtual bool verifySignature(const String &, const String &) =0;
		virtual String seal(const String &, long) throw (IntegrityException) =0;
		virtual String unseal(const String &) =0;
		virtual bool verifySeal(const String &) =0;
		virtual long getRelativeTimeStamp(long) =0;
		virtual long getTimeStamp() =0;

  protected:
    explicit Encryptor() {};

  public:
		virtual ~Encryptor() {};
	};
};


