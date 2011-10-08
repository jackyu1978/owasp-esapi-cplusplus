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

#include "errors/IllegalArgumentException.h"
using esapi::IllegalArgumentException;

#include "util/SecureArray.h"
using esapi::SecureByteArray;

#include <crypto/IvParameterSpec.h>
using esapi::IvParameterSpec;

BOOST_AUTO_TEST_CASE(IvParameterTest_1P)
{
  try
    {
      const byte arr[] = { 0, 1, 2, 3 };
      IvParameterSpec iv(arr, COUNTOF(arr));

      SecureByteArray sa = iv.getIV();

      BOOST_CHECK(sa.size() == COUNTOF(arr));
      BOOST_CHECK(0 == memcmp(arr, sa.data(), sa.size()));
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

BOOST_AUTO_TEST_CASE(IvParameterTest_2P)
{
  try
    {
      const byte arr[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
      SecureByteArray sa1(arr, COUNTOF(arr));

      IvParameterSpec iv(sa1);
      SecureByteArray sa2 = iv.getIV();

      BOOST_CHECK(sa1.size() == COUNTOF(arr));
      BOOST_CHECK(sa2.size() == COUNTOF(arr));
      BOOST_CHECK(0 == memcmp(sa1.data(), sa2.data(), sa1.size()));
    }
  catch(const std::exception& ex)
    {
      BOOST_ERROR(ex.what());
    }
  catch(...)
    {
      BOOST_ERROR("Caught unknown exception");
    }
}

