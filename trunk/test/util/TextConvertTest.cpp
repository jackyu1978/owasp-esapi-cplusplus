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
static const NarrowString narrow("\xe9\xaa\xa8");

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

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < narrow.length(); ii++)
    oss << " " << std::hex << int(0xFF & narrow[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << std::hex << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == narrow, "Failed the Chinese Bone Test (1). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_4P )
{
  // Han character for 'bone'
  NarrowString n(narrow);
  WideString w = TextConvert::NarrowToWide(n);

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < wide.length(); ii++)
    oss << " " << std::hex << int(0xFFFF & wide[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << std::hex << int(0xFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == wide, "Failed the Chinese Bone Test (2). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_5P )
{
  // Han character for 'bone'
  NarrowString n(narrow);
  WideString w = TextConvert::NarrowToWide(n, "UTF-8");

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < wide.length(); ii++)
    oss << " " << std::hex << int(0xFFFF & wide[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << std::hex << int(0xFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == wide, "Failed the Chinese Bone Test (2). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_6P )
{
  // Han character for 'bone'
  WideString w(wide);
  NarrowString n = TextConvert::WideToNarrow(w, "UTF-8");

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < narrow.length(); ii++)
    oss << " " << std::hex << int(0xFF & narrow[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << std::hex << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == narrow, "Failed the Chinese Bone Test (1). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_7N )
{
  bool success = false;

  try
  {
    // Han character for 'bone'
    NarrowString n(narrow);
    WideString w = TextConvert::NarrowToWide(n, "Junk");
  }
  catch(const InvalidArgumentException&)
  {
    success = true;
  }

  BOOST_CHECK_MESSAGE(success, "Failed to detect bad encoding request");
}

BOOST_AUTO_TEST_CASE( TextConvertTest_8N )
{
  bool success = false;

  try
  {
    // Han character for 'bone'
    WideString w(wide);
    NarrowString n = TextConvert::NarrowToWide(w, "Junk");
  }
  catch(const InvalidArgumentException&)
  {
    success = true;
  }

  BOOST_CHECK_MESSAGE(success, "Failed to detect bad encoding request");
}
