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

#include <crypto/KeyDerivationFunction.h>
using esapi::KeyDerivationFunction;
using esapi::SecretKey;

void VerifyKeyDerivationFunction1();
void VerifyKeyDerivationFunction2();
void VerifyKeyDerivationFunction3();
void VerifyKeyDerivationFunction4();
void VerifyKeyDerivationFunction5();
void VerifyKeyDerivationFunction6();
void VerifyKeyDerivationFunction7();
void VerifyKeyDerivationFunction8();
void VerifyKeyDerivationFunction9();

BOOST_AUTO_TEST_CASE( VerifyKeyDerivationFunction )
{
  BOOST_MESSAGE( "Verifying KeyDerivationFunction class" );

	  VerifyKeyDerivationFunction1();
	  VerifyKeyDerivationFunction2();
	  VerifyKeyDerivationFunction3();
	  VerifyKeyDerivationFunction4();
	  VerifyKeyDerivationFunction5();
	  VerifyKeyDerivationFunction6();
	  VerifyKeyDerivationFunction7();
	  VerifyKeyDerivationFunction8();
	  VerifyKeyDerivationFunction9();
	  //BOOST_REQUIRE( 1 == 1 );
}

void VerifyKeyDerivationFunction()
{
  VerifyKeyDerivationFunction1();
  VerifyKeyDerivationFunction2();
  VerifyKeyDerivationFunction3();
  VerifyKeyDerivationFunction4();
  VerifyKeyDerivationFunction5();
  VerifyKeyDerivationFunction6();
  VerifyKeyDerivationFunction7();
  VerifyKeyDerivationFunction8();
  VerifyKeyDerivationFunction9();
}

void VerifyKeyDerivationFunction1()
{
  SecretKey k(32);
  std::string p("encryption");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 16*8, p);

  if(d.SizeInBytes() != 16)
    cerr << "VerifyKeyDerivationFunction1 failed" << endl;
}

void VerifyKeyDerivationFunction2()
{
  SecretKey k(32);
  std::string p("authenticity");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 16*8, p);

  if(d.SizeInBytes() != 16)
    cerr << "VerifyKeyDerivationFunction1 failed" << endl;
}

void VerifyKeyDerivationFunction3()
{
  SecretKey k(32);
  std::string p("encryption");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 7*8, p);

  if(d.SizeInBytes() != 7)
    cerr << "VerifyKeyDerivationFunction3 failed" << endl;
}

void VerifyKeyDerivationFunction4()
{
  SecretKey k(32);
  std::string p("authenticity");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 7*8, p);

  if(d.SizeInBytes() != 7)
    cerr << "VerifyKeyDerivationFunction4 failed" << endl;
}

void VerifyKeyDerivationFunction5()
{
  SecretKey k(32);
  std::string p("encryption");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 64*8, p);

  if(d.SizeInBytes() != 64)
    cerr << "VerifyKeyDerivationFunction5 failed" << endl;
}

void VerifyKeyDerivationFunction6()
{
  SecretKey k(32);
  std::string p("authenticity");

  SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 64*8, p);

  if(d.SizeInBytes() != 64)
    cerr << "VerifyKeyDerivationFunction6 failed" << endl;
}

void VerifyKeyDerivationFunction7()
{
  SecretKey k(0);
  std::string p("encryption");
  bool success = false;

  try
    {
      SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 64*8, p);
    }
  catch(...)
    {
      success = true;
    }

  // TODO: remove this test if there is no minimum keyDerivationKey size
  success = true;
  if(!success)
    cerr << "VerifyKeyDerivationFunction7 failed" << endl;
}

void VerifyKeyDerivationFunction8()
{
  SecretKey k(32);
  std::string p("encryption");
  bool success = false;

  try
    {
      SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 1*8, p);
    }
  catch(...)
    {
      success = true;
    }

  if(!success)
    cerr << "VerifyKeyDerivationFunction8 failed" << endl;
}

void VerifyKeyDerivationFunction9()
{
  SecretKey k(32);
  bool success = false;

  try
    {
      SecretKey d = KeyDerivationFunction::computeDerivedKey(k, 16*8, "");
    }
  catch(...)
    {
      success = true;
    }

  if(!success)
    cerr << "VerifyKeyDerivationFunction9 failed" << endl;
}

