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
*/

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;
using esapi::NarrowString;
using esapi::WideString;

#include <util/TextConvert.h>
using esapi::TextConvert;

static const WideString wide = L"\u9aa8";

static const char chars[] = { (char)0xe9, (char)0xaa, (char)0xa8, 0x00 };
static const NarrowString narrow(chars);

BOOST_AUTO_TEST_CASE( TextConvertTest_1P )
{
  WideString w(1, L'a');
  NarrowString n = TextConvert::WideToNarrow(w);

  char expected = 'a';
  BOOST_CHECK_MESSAGE(0 == ::memcmp(n.data(), &expected, sizeof(char)), "Failed to down convert letter 'a'");
}

BOOST_AUTO_TEST_CASE( TextConvertTest_2P )
{
  NarrowString n(1, 'a');
  WideString w = TextConvert::NarrowToWide(n);

  wchar_t expected = L'a';
  BOOST_CHECK_MESSAGE(0 == ::memcmp(w.data(), &expected, sizeof(wchar_t)), "Failed to up convert letter 'a'");
}

BOOST_AUTO_TEST_CASE( TextConvertTest_3P )
{
  // Han character for 'bone'
  WideString w(wide);
  NarrowString n = TextConvert::WideToNarrow(w);

  BOOST_CHECK_MESSAGE(n == narrow, "Failed the Chinese Bone Test (1)");
}

BOOST_AUTO_TEST_CASE( TextConvertTest_4P )
{
  // Han character for 'bone'
  NarrowString n(narrow);
  WideString w = TextConvert::NarrowToWide(n);

  BOOST_CHECK_MESSAGE(w == wide, "Failed the Chinese Bone Test (2)");
}

