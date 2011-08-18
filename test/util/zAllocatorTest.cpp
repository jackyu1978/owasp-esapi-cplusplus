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

#if !defined(ESAPI_OS_WINDOWS)
# define BOOST_TEST_DYN_LINK
# include <boost/test/unit_test.hpp>
using namespace boost::unit_test;
#endif

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <vector>
using std::vector;

#include <list>
using std::list;

#include <algorithm>
using std::equal;

#include <sstream>
using std::ostringstream;

#include <EsapiCommon.h>
#include <util/zAllocator.h>
using esapi::zallocator;
using esapi::SecureByteArray;
using esapi::SecureIntArray;

void VerifyAllocationWrap();
void VerifyListAllocation();

void VerifySecureByteArray();
void VerifySecureIntArray();

class Useless
{
public:
  Useless() { }
  virtual ~Useless() { }
  
private:
  byte unused[4096];
};

BOOST_AUTO_TEST_CASE( VerifyAllocator )
{
  BOOST_MESSAGE( "Verifying zAllocator class" );

  VerifyAllocationWrap();
  VerifyListAllocation();
  VerifySecureByteArray();
  VerifySecureIntArray();
}

void VerifyAllocationWrap()
{
  bool success = false;

  // Negative
  try
    {
      success = false;
      const size_t excess = (std::numeric_limits<size_t>::max() / sizeof(Useless)) << 2;
      std::vector< Useless, zallocator<Useless> > vv (excess);
    }
  catch(std::exception&)
    {
      success = true;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch wrap");
        
}

void VerifyListAllocation()
{
  bool success = false;
  try
    {
      success = false;
      std::list< int, zallocator<int> > ll;

      success = (ll.size() == 0);
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Unexpected list");

  try
    {
      success = false;
      std::list< int, zallocator<int> > ll;
      ll.push_front(1);

      success = (ll.size() == 1);
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to insert into list");

  try
    {
      success = true;
      std::list< int, zallocator<int> > ll;
      ll.push_front(1);
      ll.push_front(2);

      std::list< int, zallocator<int> >::const_iterator it = ll.begin();
      success |= (*it == 1);
      it++;
      success |= (*it == 2);
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to iterate list");

  try
    {
      success = false;
      std::list< int, zallocator<int> > ll;
      ll.push_front(1);
      ll.push_front(2);

      std::list< int > kk;
      kk.push_front(1);
      kk.push_front(2);

      success = equal(ll.begin(), ll.end(), kk.begin());
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to compare lists");

  try
    {
      success = false;
      std::list< int, zallocator<int> > ll;
      ll.push_front(1);
      ll.push_front(2);

      std::list< int > kk;
      kk.push_front(2);
      kk.push_front(1);

      success = !equal(ll.begin(), ll.end(), kk.begin());
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to compare lists");

  try
    {
      success = false;
      std::list< int, zallocator<int> > ll;

      ll.push_front(1);
      ll.push_front(2);
      ll.push_front(3);
      ll.push_front(4);

      std::list< int > kk;
      kk.push_front(1);
      kk.push_front(2);

      success = !equal(ll.begin(), ll.end(), kk.begin());
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to compare lists");

  try
    {
      success = true;
      std::list< int, zallocator<int> > ll;

      ll.push_front(1);
      ll.push_front(2);

      std::list< int, zallocator<int> >::iterator it = ll.begin();
      success |= (*it == 1);

      ll.erase(it);
      it = ll.begin();
      
      success |= (*it == 2);

      it = ll.end();
      success |= (*(--it) == 2);

      ll.erase(it);
      success |= (ll.size() == 0);
    }
  catch(std::exception&)
    {
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to compare lists");
}

void VerifySecureByteArray()
{
  bool success = false;

  // Negative (can't run this test)
  // memory access violation at address: 0x00000000: no mapping at fault address
  // try
  //  {
  //    success = false;
  //    SecureByteArray vv;
  //    byte p = vv[0];
  //  }
  //catch(...)
  //  {
  //    success = true;
  //  }
  // BOOST_CHECK_MESSAGE(success, "Failed to catch empty operator[]");

  // Negative
  try
    {
      success = false;
      SecureByteArray vv;
      byte p = vv.at(0);
    }
  catch(std::exception&)
    {
      success = true;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch empty at()");

  // Negative (can't run this test)
  // memory access violation at address: 0x00000000: no mapping at fault address
  // try
  //  {
  //    success = false;
  //    SecureByteArray vv;
  //    byte* pb = &vv[0];
  //  }
  //catch(std::exception&)
  //  {
  //    success = true;
  //  }
  // BOOST_CHECK_MESSAGE(success, "Failed to catch address of empty array");

  // Positive
  try
    {
      success = false;
      SecureByteArray vv(1);

      success = (0 == vv.at(0));
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureByteArray vv(1);

      success = (0 == vv[0]);
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureByteArray vv(1);

      byte* pb = &vv[0];

      success = (0 == *pb);
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureByteArray vv;
      vv.push_back(1);

      success = (1 == vv[0]);
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureByteArray vv;
      vv.push_back(1);

      success = (1 == vv.at(0));
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureByteArray vv;
      vv.push_back(1);
      vv.push_back(2);
      vv.push_back(3);

      success = (3 == vv.size());
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed size() test");

  // Positive
  try
    {
      success = false;

      SecureByteArray vv;
      vv.push_back(1);
      vv.push_back(2);
      vv.push_back(3);

      std::vector< byte > uu;
      uu.push_back(1);
      uu.push_back(2);
      uu.push_back(3);

      success = equal(vv.begin(), vv.end(), uu.begin());
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed equal array test");

  // Positive
  try
    {
      success = false;

      SecureByteArray vv;
      vv.push_back(1);
      vv.push_back(2);

      std::vector< byte > uu;
      uu.push_back(2);
      uu.push_back(1);

      success = !equal(vv.begin(), vv.end(), uu.begin());
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed equal array test");

}

void VerifySecureIntArray()
{
  bool success = false;

  // Negative (can't run this test)
  // memory access violation at address: 0x00000000: no mapping at fault address
  // try
  //  {
  //    success = false;
  //    SecureIntArray vv;
  //    byte p = vv[0];
  //  }
  //catch(...)
  //  {
  //    success = true;
  //  }
  //catch(...)
  //  {
  //    cerr << "Caught unknown exception" << endl;
  //  }
  // BOOST_CHECK_MESSAGE(success, "Failed to catch empty operator[]");

  // Negative
  try
    {
      success = false;
      SecureIntArray vv;
      byte p = vv.at(0);
    }
  catch(std::exception&)
    {
      success = true;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed to catch empty at()");

  // Negative (can't run this test)
  // memory access violation at address: 0x00000000: no mapping at fault address
  // try
  //  {
  //    success = false;
  //    SecureIntArray vv;
  //    byte* pb = &vv[0];
  //  }
  //catch(std::exception&)
  //  {
  //    success = true;
  //  }
  //catch(...)
  //  {
  //    cerr << "Caught unknown exception" << endl;
  //  }
  // BOOST_CHECK_MESSAGE(success, "Failed to catch address of empty array");

  // Positive
  try
    {
      success = false;
      SecureIntArray vv(1);

      success = (0 == vv.at(0));
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureIntArray vv(1);

      success = (0 == vv[0]);
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureIntArray vv(1);
      int* pi = &vv[0];

      success = (0 == *pi);
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureIntArray vv;
      vv.push_back(1);

      success = (1 == vv[0]);
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureIntArray vv;
      vv.push_back(1);

      success = (1 == vv.at(0));
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed single element test");

  // Positive
  try
    {
      success = false;
      SecureIntArray vv;
      vv.push_back(1);
      vv.push_back(2);
      vv.push_back(3);

      success = (3 == vv.size());
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed size() test");

  // Positive
  try
    {
      success = false;

      SecureIntArray vv;
      vv.push_back(1);
      vv.push_back(2);
      vv.push_back(3);

      std::vector< byte > uu;
      uu.push_back(1);
      uu.push_back(2);
      uu.push_back(3);

      success = equal(vv.begin(), vv.end(), uu.begin());
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed equal array test");

  // Positive
  try
    {
      success = false;

      SecureIntArray vv;
      vv.push_back(2);
      vv.push_back(1);

      std::vector< byte > uu;
      uu.push_back(1);
      uu.push_back(2);

      success = !equal(vv.begin(), vv.end(), uu.begin());
    }
  catch(std::exception& ex)
    {
      cerr << "Caught " << ex.what() << endl;
    }
  catch(...)
    {
      cerr << "Caught unknown exception" << endl;
    }
  BOOST_CHECK_MESSAGE(success, "Failed equal array test");
}

