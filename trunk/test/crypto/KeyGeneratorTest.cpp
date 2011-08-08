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

static const unsigned int KEY_SIZES[] = { 63, 64, 65, 80, 112, 128, 192, 256, 384, 512 };

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

BOOST_AUTO_TEST_CASE( test_case_KeyGenerator )
{
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
      cerr << "  Key 1 is too small: " << k1 << endl;

    SecretKey k2 = kgen->generateKey();
    if(k2.SizeInBytes() < bytes)
      cerr << "  Key 2 is too small: " << k2 << endl;

    #if defined(DUMP_KEYS)
      cout << " " << k1 << endl;
    #endif

    if(k1 == k2)
       cerr << "  Key 1 equals key 2: " << k1 << endl;

    #if defined(DUMP_KEYS)
      cout << " " << k2 << endl;
    #endif
}

void VerifyAesKeyGenerator()
{
    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "aes";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyCamelliaKeyGenerator()
{
    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "CameLLia";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyDesEdeKeyGenerator()
{
    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "DeSEdE";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyBlowfishKeyGenerator()
{
    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "BlowFISH";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyShaKeyGenerator()
{
    string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "SHA1";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyWhirlpoolKeyGenerator()
{
    string alg = "Whirlpool";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyHmacShaKeyGenerator()
{
	string alg;

    ///////////////////////////////////////////////////////////////////////

    alg = "HmacSHA1";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
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

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyHmacWhirlpoolKeyGenerator()
{
    string alg = "HmacWhirlpool";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

void VerifyArc4KeyGenerator()
{
    string alg = "ArcFour";

    for(size_t i = 0; i < COUNTOF(KEY_SIZES); i++)
    {
        auto_ptr<KeyGenerator> kg(KeyGenerator::getInstance(alg));

        const unsigned int bits = KEY_SIZES[i];
        const unsigned int bytes = (bits+7)/8;
        kg->init(bits);

        cout << "Testing " << kg->algorithm() << " (" << bits << ")" << endl;
        VerifyKeyGeneration(kg, bytes);
    }
}

