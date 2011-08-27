/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author Daniel Amodio, dan.amodio@aspectsecurity.com
 *
 */

#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include "EsapiCommon.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <map>
#include <set>

#include <sstream>
using std::stringstream;
using std::istringstream;
using std::ostringstream;

#include "codecs/HashTrie.h"
using esapi::HashTrie;


BOOST_AUTO_TEST_CASE( HashTrieTestCase )
{
	esapi::HashTrie<int>::Entry<int> htentry("asdf", 123);
    std::pair<std::string,int> pair(std::string("asdf"),123);
	BOOST_CHECK(htentry.equals(pair));
}
