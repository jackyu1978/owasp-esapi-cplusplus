#ifndef _CryptoppEncryptor_h_
#define _CryptoppEncryptor_h_

#include <string>
#include <cstdio>

#include <Encryptor.h>

class CryptoppEncryptor: esapi::Encryptor
{
	// hashing
	static std::string hashAlgorithm = "SHA-512";
	static int hashIterations = 1024;

public:
	virtual std::string hash(const std::string &plaintext, const std::string &salt)
	{
		return hash( plaintext, salt, hashIterations );
	}

	virtual std::string hash(const std::string &plaintext, const std::string &salt, int iterations)
	{
		std::string encoded;

		MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
		byte bytes[digest::DIGESTSIZE];
		try {
			digest.Update(ESAPI.securityConfiguration().getMasterSalt());
			digest.Update(salt.getBytes(encoding));
			digest.Update(plaintext.getBytes(encoding));

			// rehash a number of times to help strengthen weak passwords
			digest.Final(bytes);
			for (int i = 0; i < iterations; i++) {
				digest.Update(bytes);
				digest.Final(bytes);
			}
			CryptoPP::StringSource(bytes, false, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded)));
			return encoded;
		} catch (NoSuchAlgorithmException& e) {
			throw new EncryptionException("Internal error", "Can't find hash algorithm " + hashAlgorithm, e);
		} catch (UnsupportedEncodingException& ex) {
			throw new EncryptionException("Internal error", "Can't find encoding for " + encoding, ex);
		}
	}

	virtual CipherText encrypt(PlainText)
	{

	}

	virtual CipherText encrypt(SecretKey, PlainText)
	{

	}

	virtual PlainText decrypt(CipherText)
	{

	}

	virtual PlainText decrypt(SecretKey, CipherText)
	{

	}

	virtual std::string sign(const std::string &)
	{

	}

	virtual std::string seal(const std::string &, long)
	{

	}

	virtual std::string unseal(const std::string &)
	{

	}

	virtual bool verifyseal(const std::string &)
	{

	}

	virtual long getRelativeTimeStamp(long)
	{

	}

	virtual long getTimeStamp()
	{

	}

};

#endif	// _CryptoppEncryptor_h_
