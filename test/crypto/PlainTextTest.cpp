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

#include "EsapiCommon.h"
using esapi::NarrowString;
using esapi::String;

#include "util/SecureArray.h"
using esapi::SecureByteArray;

#include "util/TextConvert.h"
using esapi::TextConvert;

#include <crypto/PlainText.h>
using esapi::PlainText;

BOOST_AUTO_TEST_CASE( VerifyPlainText )
{
  BOOST_MESSAGE("Verifying PlainText class");
}

BOOST_AUTO_TEST_CASE(VerifyPlainTextFunction1) //:Test assignment and comparison.
{
  String unicodeStr = L"A\u00ea\u00f1\u00fcC";     //:"AêñüC"
  String altString = TextConvert::NarrowToWide("AêñüC");     //:Same as above.
  PlainText str1(unicodeStr), str2(altString);
  BOOST_CHECK(str1.equals(str1));
  BOOST_CHECK(str1.equals(str2));
  BOOST_CHECK(!str1.toString().empty());
  BOOST_CHECK(str2.toString() == altString);
  BOOST_CHECK(str1.toString() == unicodeStr);
  BOOST_CHECK(str2.length() == altString.length());
}

BOOST_AUTO_TEST_CASE(VerifyPlainTextFunction2) //:Test Empty String.
{
PlainText pt(L"");
BOOST_CHECK(pt.toString() == L"");
BOOST_CHECK(pt.length() == 0);
SecureByteArray bytes = pt.asBytes();
BOOST_CHECK(bytes.length() == 0);
}

BOOST_AUTO_TEST_CASE(VerifyPlainTextFunction3) //:Test Overwrite
{
String unicodeStr = TextConvert::NarrowToWide("A\u00ea\u00f1\u00fcC");
SecureByteArray origBytes = TextConvert::GetBytes(unicodeStr);
PlainText pt(origBytes);
BOOST_CHECK(pt.toString() == unicodeStr);
//BOOST_CHECK(origBytes == pt.asBytes());  //:Can't compare SecureByteArrays with == operator
size_t origLen = origBytes.length();
pt.overwrite();
SecureByteArray overwrittenBytes = pt.asBytes();
size_t afterLen = overwrittenBytes.length();
BOOST_CHECK(origLen == afterLen);
size_t sum = 0;
for(size_t i = 0; i < afterLen; i++)
   if(overwrittenBytes[i] == L'*')
      sum++;
BOOST_CHECK(sum == afterLen);
}