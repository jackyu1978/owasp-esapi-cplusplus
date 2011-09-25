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
#include <iomanip>
using std::cout;
using std::cerr;
using std::endl;

#include "EsapiCommon.h"
using esapi::Char;
using esapi::String;
using esapi::NarrowString;
using esapi::WideString;

#include <errors/InvalidArgumentException.h>
using esapi::InvalidArgumentException;

#include <util/TextConvert.h>
using esapi::TextConvert;

#define HEX(x) std::hex << std::setw(x) << std::setfill('0')

static const WideString wide = L"\u9aa8";
static const NarrowString narrow("\xe9\xaa\xa8");

BOOST_AUTO_TEST_CASE( TextConvertTest_1P )
{
  WideString w(1, L'a');
  NarrowString n = TextConvert::WideToNarrow(w);
  NarrowString e(1, 'a');

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == e, "Failed to down convert letter 'a'. " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_2P )
{
  NarrowString n(1, 'a');
  WideString w = TextConvert::NarrowToWide(n);
  WideString e(1, L'a');

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == e, "Failed to up convert letter 'a'. " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_3P )
{
  WideString w(L"a");
  NarrowString n = TextConvert::WideToNarrow(w);
  NarrowString e("a");

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == e, "Failed to down convert letter 'a'. " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_4P )
{
  NarrowString n("a");
  WideString w = TextConvert::NarrowToWide(n);
  WideString e(L"a");

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == e, "Failed to up convert letter 'a'. " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_5P )
{
  WideString w(L"aa");
  NarrowString n = TextConvert::WideToNarrow(w);
  NarrowString e("aa");

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == e, "Failed to down convert 'aa'. " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_6P )
{
  NarrowString n("aa");
  WideString w = TextConvert::NarrowToWide(n);
  WideString e(L"aa");

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == e, "Failed to up convert 'aa'. " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_7P )
{
  // Han character for 'bone'
  WideString w(wide);
  NarrowString n = TextConvert::WideToNarrow(w);
  NarrowString e(narrow);

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == e, "Failed the Chinese Bone Test (1). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_8P )
{
  // Han character for 'bone'
  NarrowString n(narrow);
  WideString w = TextConvert::NarrowToWide(n);
  WideString e(wide);

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == e, "Failed the Chinese Bone Test (2). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_9P )
{
  // Han character for 'bone'
  NarrowString n(narrow);
  WideString w = TextConvert::NarrowToWide(n, "UTF-8");
  WideString e(wide);

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < w.length(); ii++)
    oss << " " << HEX(4) << int(0xFFFF & w[ii]);

  BOOST_CHECK_MESSAGE(w == e, "Failed the Chinese Bone Test (3). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_10P )
{
  // Han character for 'bone'
  WideString w(wide);
  NarrowString n = TextConvert::WideToNarrow(w, "UTF-8");
  NarrowString e(narrow);

  std::ostringstream oss;
  oss << "Expected";
  for(size_t ii = 0; ii < e.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & e[ii]);

  oss << ", got ";
  for(size_t ii = 0; ii < n.length(); ii++)
    oss << " " << HEX(2) << int(0xFF & n[ii]);

  BOOST_CHECK_MESSAGE(n == e, "Failed the Chinese Bone Test (4). " + oss.str());
}

BOOST_AUTO_TEST_CASE( TextConvertTest_11N )
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

BOOST_AUTO_TEST_CASE( TextConvertTest_12N )
{
  bool success = false;

  try
    {
      // Han character for 'bone'
      WideString w(wide);
      NarrowString n = TextConvert::WideToNarrow(w, "Junk");
    }
  catch(const InvalidArgumentException&)
    {
      success = true;
    }

  BOOST_CHECK_MESSAGE(success, "Failed to detect bad encoding request");
}

BOOST_AUTO_TEST_CASE( TextConvertTest_13P )
{
  // Han character for 'bone'
  NarrowString n;
  WideString e;
  for( unsigned int jj = 0; jj < 4096; jj++)
    {
      n += narrow;
      e += wide;
    }

  try
    {
      WideString w = TextConvert::NarrowToWide(n);

      std::ostringstream oss;
      size_t kk = std::min(std::min(e.length(), w.length()), (size_t)16);

      oss << "Expected";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(4) << int(0xFFFF & e[ii]);
      oss << ", ...";

      oss << ", got ";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(4) << int(0xFFFF & w[ii]);
      oss << ", ...";

      BOOST_CHECK_MESSAGE(w == e, "Failed the Chinese Bone Test (1, 0, repeat). " + oss.str());
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
}

BOOST_AUTO_TEST_CASE( TextConvertTest_14P )
{
  // Han character for 'bone'
  WideString w;
  NarrowString e;
  for( unsigned int jj = 0; jj < 4096; jj++)
    {
      w += wide;
      e += narrow;
    }

  try
    {
      NarrowString n = TextConvert::WideToNarrow(w);

      std::ostringstream oss;
      size_t kk = std::min(std::min(e.length(), n.length()), (size_t)16);

      oss << "Expected";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(2) << int(0xFF & n[ii]);
      oss << ", ...";

      oss << ", got ";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(2) << int(0xFF & e[ii]);
      oss << ", ...";

      BOOST_CHECK_MESSAGE(n == e, "Failed the Chinese Bone Test (2, 0, repeat). " + oss.str());
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
}

BOOST_AUTO_TEST_CASE( TextConvertTest_15P )
{
  // Han character for 'bone'
  NarrowString n("a");
  WideString e(L"a");
  for( unsigned int jj = 0; jj < 4096; jj++)
    {
      n += narrow;
      e += wide;
    }

  try
    {
      WideString w = TextConvert::NarrowToWide(n);

      std::ostringstream oss;
      size_t kk = std::min(std::min(e.length(), w.length()), (size_t)16);

      oss << "Expected";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(4) << int(0xFFFF & e[ii]);
      oss << ", ...";

      oss << ", got ";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(4) << int(0xFFFF & w[ii]);
      oss << ", ...";

      BOOST_CHECK_MESSAGE(w == e, "Failed the Chinese Bone Test (3, 1, repeat). " + oss.str());
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
}

BOOST_AUTO_TEST_CASE( TextConvertTest_16P )
{
  // Han character for 'bone'
  WideString w(L"a");
  NarrowString e("a");
  for( unsigned int jj = 0; jj < 4096; jj++)
    {
      w += wide;
      e += narrow;
    }

  try
    {
      NarrowString n = TextConvert::WideToNarrow(w);

      std::ostringstream oss;
      size_t kk = std::min(std::min(e.length(), n.length()), (size_t)16);

      oss << "Expected";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(2) << int(0xFF & n[ii]);
      oss << ", ...";

      oss << ", got ";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(2) << int(0xFF & e[ii]);
      oss << ", ...";

      BOOST_CHECK_MESSAGE(n == e, "Failed the Chinese Bone Test (4, 1, repeat). " + oss.str());
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
}

BOOST_AUTO_TEST_CASE( TextConvertTest_17P )
{
  // Han character for 'bone'
  NarrowString n("aa");
  WideString e(L"aa");
  for( unsigned int jj = 0; jj < 4096; jj++)
    {
      n += narrow;
      e += wide;
    }

  try
    {
      WideString w = TextConvert::NarrowToWide(n);

      std::ostringstream oss;
      size_t kk = std::min(std::min(e.length(), w.length()), (size_t)16);

      oss << "Expected";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(4) << int(0xFFFF & e[ii]);
      oss << ", ...";

      oss << ", got ";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(4) << int(0xFFFF & w[ii]);
      oss << ", ...";

      BOOST_CHECK_MESSAGE(w == e, "Failed the Chinese Bone Test (5, 2, repeat). " + oss.str());
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
}

BOOST_AUTO_TEST_CASE( TextConvertTest_18P )
{
  // Han character for 'bone'
  WideString w(L"aa");
  NarrowString e("aa");
  for( unsigned int jj = 0; jj < 4096; jj++)
    {
      w += wide;
      e += narrow;
    }

  try
    {
      NarrowString n = TextConvert::WideToNarrow(w);

      std::ostringstream oss;
      size_t kk = std::min(std::min(e.length(), n.length()), (size_t)16);

      oss << "Expected";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(2) << int(0xFF & n[ii]);
      oss << ", ...";

      oss << ", got ";
      for(size_t ii = 0; ii < kk; ii++)
        oss << " " << HEX(2) << int(0xFF & e[ii]);
      oss << ", ...";

      BOOST_CHECK_MESSAGE(n == e, "Failed the Chinese Bone Test (6, 2, repeat). " + oss.str());
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
}

