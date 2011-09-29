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
 * @author Andrew Durkin, atdurkin@gmail.com
 */

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <exception>
using std::exception;

#include "EsapiCommon.h"
using esapi::String;

#include "errors/IllegalArgumentException.h"
using esapi::IllegalArgumentException;

#include "util/SecureArray.h"
using esapi::SecureByteArray;

#include <crypto/CipherSpec.h>
using esapi::CipherSpec;

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction1) //:Test correct construction.
{
SecureByteArray myIV;
CipherSpec cs(L"AES/CBC/NoPadding", 128, 8, myIV);
BOOST_CHECK(cs.getCipherTransformation() == L"AES/CBC/NoPadding");
BOOST_CHECK(cs.getKeySize() == 128);
BOOST_CHECK(cs.getBlockSize() == 8);
}


BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction2) //:Test empty cipher XForm.
{
SecureByteArray myIV;
bool caughtExcept = false;
     try
     {
     CipherSpec cs(L"", 128, 8, myIV);
     }
     catch(const IllegalArgumentException&)
     {
     caughtExcept = true;
     }
BOOST_CHECK(caughtExcept);
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction3) //:Missing padding scheme.
{
SecureByteArray myIV;
bool caughtExcept = false;
     try
     {
     CipherSpec cs(L"AES/CBC", 128, 8, myIV);
     }
     catch(const IllegalArgumentException&)
     {
     caughtExcept = true;
     }
BOOST_CHECK(caughtExcept);
}


BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction4) //:Checking CipherSpec(SecureByteArray &b) CTOR.
{
  SecureByteArray myIV;
  CipherSpec cs(myIV);
  //BOOST_CHECK(cs.getkeySize() == ESAPI.securityConfiguration().getEncryptionKeyLength());
  //BOOST_CHECK(cs.getCipherTransformation() == ESAPI.securityConfiguration().getCipherTransformation());
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction5) //:Checking set and get CipherTransformation().
{
CipherSpec cs(L"AlgName/Mode/Padding", 128);
BOOST_CHECK(cs.getCipherTransformation() == L"AlgName/Mode/Padding");
bool caughtExcept = false;
     try
     {
     cs.setCipherTransformation(L"");
     }
     catch(const IllegalArgumentException&)
     {
     caughtExcept = true;
     }
BOOST_CHECK(caughtExcept);
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction6) //:Testing a bunch of get functions.
{
CipherSpec cs(L"Alg/Mode/Padding", 128, 8);
BOOST_CHECK(cs.getKeySize() == 128);
BOOST_CHECK(cs.getBlockSize() == 8);
BOOST_CHECK(cs.getCipherTransformation() == L"Alg/Mode/Padding");
BOOST_CHECK(cs.getCipherAlgorithm() == L"Alg");
BOOST_CHECK(cs.getCipherMode() == L"Mode");
BOOST_CHECK(cs.getPaddingScheme() == L"Padding");
}


BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction7) //:Testing setBlockSize().
{
CipherSpec cs;
bool caughtExcept = false;
     try
     {
     cs.setBlockSize(0);
     }
     catch(const IllegalArgumentException&)
     {
     caughtExcept = true;
     }
BOOST_CHECK(caughtExcept);
caughtExcept = false;
     try
     {
     cs.setBlockSize(-1);
     }
     catch(const IllegalArgumentException&)
     {
     caughtExcept = true;
     }
BOOST_CHECK(caughtExcept);
}

BOOST_AUTO_TEST_CASE(VerifyCipherSpecFunction8) //:Testing requiresIV().
{
CipherSpec cs(L"Alg/EcB/Padding", 128);
BOOST_CHECK(cs.getCipherMode() == L"EcB");
BOOST_CHECK(cs.requiresIV() == false);
cs.setCipherTransformation(L"Alg/NotECB/Padding");
BOOST_CHECK(cs.requiresIV() == true);
}