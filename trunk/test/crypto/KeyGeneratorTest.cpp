#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

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

void VerifyKeyGenerator()
{
	auto_ptr<KeyGenerator> t1(KeyGenerator::getInstance("AES/CBC/PKCS5"));
	t1->init(128);
    cout << t1->algorithm() << endl;

	SecretKey k1 = t1->generateKey();
}

