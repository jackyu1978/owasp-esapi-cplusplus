/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Kevin Wall, kevin.w.wall@gmail.com
 * @author Jeffrey Walton, noloader@gmail.com
 * @author David Anderson, david.anderson@aspectsecurity.com
 */

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include <string>
using std::string;

#include <memory>
using std::auto_ptr;

#include <crypto/SecretKey.h>
#include <crypto/KeyGenerator.h>
using esapi::SecretKey;
using esapi::KeyGenerator;

static const unsigned int KEY_SIZES[] = { 1, 8, 63, 64, 65, 80, 112, 128, 192, 256, 384, 512 };

// Block ciphers
void VerifyAesKeyGenerator();
void VerifyDesEdeKeyGenerator();
void VerifyBlowfishKeyGenerator();
void VerifyCamelliaKeyGenerator();

// Hashes
void VerifyShaKeyGenerator();
void VerifyWhirlpoolKeyGenerator();

// HMACs
void VerifyHmacShaKeyGenerator();
void VerifyHmacWhirlpoolKeyGenerator();

void VerifyArc4KeyGenerator();

void VerifyKey(auto_ptr<KeyGenerator>& kgen, size_t bytes);

BOOST_AUTO_TEST_CASE( VerifyKeyGeneration )
{
	BOOST_MESSAGE( "Verifying KeyGeneration class" );

    VerifyAesKeyGenerator();
    VerifyDesEdeKeyGenerator();
    VerifyBlowfishKeyGenerator();
    VerifyCamelliaKeyGenerator();

    VerifyShaKeyGenerator();
    VerifyWhirlpoolKeyGenerator();

    VerifyHmacShaKeyGenerator();
    VerifyHmacWhirlpoolKeyGenerator();

    VerifyArc4KeyGenerator();
	  //BOOST_REQUIRE( 1 == 1 );
}

void VerifyKeyGeneration(auto_ptr<KeyGenerator>& kgen, size_t bytes)
{
    // #define DUMP_KEYS 1

    SecretKey k1 = kgen->generateKey();
    if(k1.SizeInBytes() < bytes)
      BOOST_ERROR( "  Key 1 is too small: " << k1 );

    SecretKey k2 = kgen->generateKey();
    if(k2.SizeInBytes() < bytes)
      BOOST_ERROR( "  Key 2 is too small: " << k2 );

    #if defined(DUMP_KEYS)
      BOOST_MESSAGE( "  " << k1 );
    #endif

    if(k1 == k2)
       BOOST_ERROR( "  Key 1 equals key 2: " << k1 );

    #if defined(DUMP_KEYS)
      BOOST_MESSAGE( "  " << k2 );
    #endif
}

void VerifyAesKeyGenerator()
{
	BOOST_MESSAGE( " Verifying AES" );

    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "aes";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
    
    ///////////////////////////////////////////////////////////////////////

    alg = "aes/CBC";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "aes\\cfb";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "aes/OFB";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyCamelliaKeyGenerator()
{
	BOOST_MESSAGE( " Verifying Camellia" );

    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "CameLLia";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "CameLLia/CBC";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "CameLLia\\cfb";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "CameLLia/OFB";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyDesEdeKeyGenerator()
{
	BOOST_MESSAGE( " Verifying DES EDE" );

    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "DeSEdE";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "DeSEdE/CBC";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "DeSEdE\\cfb";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "DeSEdE/OFB";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyBlowfishKeyGenerator()
{
	BOOST_MESSAGE( " Verifying Blowfish" );

    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "BlowFISH";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "BlowFISH/CBC";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "BlowFISH\\cfb";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "BlowFISH/OFB";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyShaKeyGenerator()
{
	BOOST_MESSAGE( " Verifying SHA" );

    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "SHA1";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "SHA224";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "SHA256";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "SHA384";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "SHA512";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyWhirlpoolKeyGenerator()
{
	BOOST_MESSAGE( " Verifying Whirlpool" );

    string alg = "Whirlpool";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyHmacShaKeyGenerator()
{
	BOOST_MESSAGE( " Verifying HMAC-SHA" );

	string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "HmacSHA1";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "HmacSHA224";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "HmacSHA256";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "HmacSHA384";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }

    ///////////////////////////////////////////////////////////////////////

    alg = "HmacSHA512";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyHmacWhirlpoolKeyGenerator()
{
	BOOST_MESSAGE( " Verifying HMAC-Whirlpool" );

    string alg = "HmacWhirlpool";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyArc4KeyGenerator()
{
	BOOST_MESSAGE( " Verifying ARC4" );

    string alg = "ArcFour";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        BOOST_MESSAGE( "  Testing " << kg->getAlgorithm() << " (" << bits << ")" );
        VerifyKeyGeneration(kg, bytes);
    }
}

