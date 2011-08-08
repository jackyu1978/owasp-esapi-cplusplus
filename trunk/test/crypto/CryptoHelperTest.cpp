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

#include <cstdlib>
#include <cstring>

#include <crypto/CryptoHelper.h>
using esapi::CryptoHelper;
using esapi::SecretKey;

// Success = 0, failed = non-0
int VerifyCryptoHelper70();
int VerifyCryptoHelper71();
int VerifyCryptoHelper72();

int VerifyCryptoHelper80();
int VerifyCryptoHelper81();
int VerifyCryptoHelper82();

int VerifyCryptoHelper90();
int VerifyCryptoHelper91();
int VerifyCryptoHelper92();
int VerifyCryptoHelper93();
int VerifyCryptoHelper94();
int VerifyCryptoHelper95();
int VerifyCryptoHelper96();
int VerifyCryptoHelper97();
int VerifyCryptoHelper98();

int VerifyCryptoHelper100();
int VerifyCryptoHelper101();
int VerifyCryptoHelper102();
int VerifyCryptoHelper103();
int VerifyCryptoHelper104();
int VerifyCryptoHelper105();
int VerifyCryptoHelper106();
int VerifyCryptoHelper107();
int VerifyCryptoHelper108();
int VerifyCryptoHelper109();

BOOST_AUTO_TEST_CASE( VerifyCryptoHelper )
{
	// generateSecretKey

	// computeDerivedKey tested in KeyDerivationFuntiontest.cpp

	// isCombinedCipherMode

	// isAllowedCipherMode

	// isMACRequired

	// isCipherTextMACvalid

	// overwrite 1
	VerifyCryptoHelper70();
	VerifyCryptoHelper71();
	VerifyCryptoHelper72();

	// overwrite 2
	VerifyCryptoHelper80();
	VerifyCryptoHelper81();
	VerifyCryptoHelper82();

	// copyByteArray
	VerifyCryptoHelper90();
	VerifyCryptoHelper91();
	VerifyCryptoHelper92();
	VerifyCryptoHelper93();
	VerifyCryptoHelper94();
	VerifyCryptoHelper95();
	VerifyCryptoHelper96();
	VerifyCryptoHelper97();
	VerifyCryptoHelper98();

	// arrayCompare
	VerifyCryptoHelper100();
	VerifyCryptoHelper101();
	VerifyCryptoHelper102();
	VerifyCryptoHelper103();
	VerifyCryptoHelper104();
	VerifyCryptoHelper105();
	VerifyCryptoHelper106();
	VerifyCryptoHelper107();
	VerifyCryptoHelper108();
	VerifyCryptoHelper109();
	//BOOST_REQUIRE( 1 == 1 );
}

int VerifyCryptoHelper70()
{
	bool success = false;

	byte b1[16];
	std::memset(b1, 0xFF, sizeof(b1));

	byte b2[16];
	std::memset(b2, 'A', sizeof(b2));	

	try
	{
		CryptoHelper::overwrite(b1, sizeof(b1), 'A');
		int result = std::memcmp(b1, b2, sizeof(b1));

		success = (result == 0);
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper70 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper71()
{
	bool success = false;

	try
	{
		CryptoHelper::overwrite(NULL, 16, 'A');
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper71 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper72()
{
	bool success = false;

	byte b1[16];

	try
	{
		CryptoHelper::overwrite(b1, 0, 'A');
		success = true;
	}
	catch(...)
	{		
	}

	if(!success)
		cerr << "VerifyCryptoHelper72 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper80()
{
	bool success = false;

	byte b1[16];
	std::memset(b1, 0xFF, sizeof(b1));

	byte b2[16];
	std::memset(b2, '*', sizeof(b2));	

	try
	{
		CryptoHelper::overwrite(b1, sizeof(b1));
		int result = std::memcmp(b1, b2, sizeof(b1));

		success = (result == 0);
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper80 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper81()
{
	bool success = false;

	try
	{
		CryptoHelper::overwrite(NULL, 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper81 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper82()
{
	bool success = false;

	byte b1[16];

	try
	{
		CryptoHelper::overwrite(b1, 0);
		success = true;
	}
	catch(...)
	{		
	}

	if(!success)
		cerr << "VerifyCryptoHelper82 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper90()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));

	try
	{
		CryptoHelper::copyByteArray(b1, sizeof(b1), b2, sizeof(b2), 16);
		int result = std::memcmp(b1, b2, sizeof(b1));

		success = (result == 0);
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper90 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper91()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 'A', sizeof(b1));
	std::memset(b2, 'Z', sizeof(b2));

	try
	{
		CryptoHelper::copyByteArray(b1, sizeof(b1), b2, sizeof(b2), 8);

		int result = 0;

		result |= std::memcmp(b1, b2, 8);

		byte aa[8] = { 'A','A','A','A','A','A','A','A' };
 		result |= std::memcmp(b1+8, aa, 8);

		success = (result == 0);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper91 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper92()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));

	try
	{
		CryptoHelper::copyByteArray(NULL, sizeof(b1), b2, sizeof(b2), 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper92 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper93()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));

	try
	{
		CryptoHelper::copyByteArray(b1, 0, b2, sizeof(b2), 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper93 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper94()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));

	try
	{
		CryptoHelper::copyByteArray(b1, sizeof(b1), NULL, sizeof(b2), 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper94 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper95()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));

	try
	{
		CryptoHelper::copyByteArray(b1, sizeof(b1), b2, 0, 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper95 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper96()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));

	try
	{
		CryptoHelper::copyByteArray(b1, sizeof(b1), b2, sizeof(b2), 32);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper96 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper97()
{
	bool success = false;

	byte* p = (byte*)(((size_t)-1) - 8);
	byte b[16];

	try
	{
		CryptoHelper::copyByteArray(p, 16, b, sizeof(b), 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper97 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper98()
{
	bool success = false;

	byte b[16];
	byte* p = (byte*)(((size_t)-1) - 8);	

	try
	{
		CryptoHelper::copyByteArray(b, sizeof(b), p, 16, 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper98 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper100()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = CryptoHelper::arrayCompare(b1, sizeof(b1), b2, sizeof(b2));
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper100 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper101()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0x00, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(b1, sizeof(b1), b2, sizeof(b2));
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper101 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper102()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(b1, sizeof(b1)-1, b2, sizeof(b2));
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper102 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper103()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(b1, sizeof(b1), b2, sizeof(b2)-1);
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper103 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper104()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(NULL, sizeof(b1), b2, sizeof(b2));
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper104 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper105()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(b1, 0, b2, sizeof(b2));
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper105 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper106()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(b1, sizeof(b1), NULL, sizeof(b2));
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper106 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper107()
{
	bool success = false;

	byte b1[16], b2[16];
	std::memset(b1, 0xFF, sizeof(b1));
	std::memset(b2, 0xFF, sizeof(b2));

	try
	{
		success = !CryptoHelper::arrayCompare(b1, sizeof(b1), b2, 0);
	}
	catch(...)
	{
	}

	if(!success)
		cerr << "VerifyCryptoHelper107 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper108()
{
	bool success = false;

	byte* p = (byte*)(((size_t)-1) - 8);
	byte b[16];

	try
	{
		CryptoHelper::arrayCompare(p, 16, b, sizeof(b));
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper108 failed" << endl;

	return success ? 0 : 1;
}

int VerifyCryptoHelper109()
{
	bool success = false;

	byte b[16];
	byte* p = (byte*)(((size_t)-1) - 8);	

	try
	{
		CryptoHelper::arrayCompare(b, sizeof(b), p, 16);
	}
	catch(...)
	{
		success = true;
	}

	if(!success)
		cerr << "VerifyCryptoHelper109 failed" << endl;

	return success ? 0 : 1;
}

