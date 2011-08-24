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

#include "codecs/Trie.h"
using esapi::Trie;


BOOST_AUTO_TEST_CASE( TrieTestCase )
{
	esapi::Trie<int> triemap;
	triemap.map.insert(std::pair<std::string,int>("asdf",1));
	BOOST_CHECK(triemap.map.count("asdf")>0);
	BOOST_CHECK(triemap.map.count("fdsa")==0);
    BOOST_CHECK(triemap.map.count("1")==0);

	esapi::Trie<int>::TrieProxy<int> tp;
	tp.put("asdf", 1);
	BOOST_CHECK(tp.containsKey("asdf"));
	tp.put("fdsa", 2);
	tp.put("foo", 3);
	tp.put("bar", 4);

	BOOST_CHECK(tp.containsKey("asdf"));
	BOOST_CHECK(tp.containsKey("fdsa"));
	BOOST_CHECK(tp.containsKey("foo"));
	BOOST_CHECK(tp.containsKey("bar"));
	BOOST_CHECK(!tp.containsKey("1"));
	BOOST_CHECK(!tp.containsKey("2"));
	BOOST_CHECK(!tp.containsKey("3"));
	BOOST_CHECK(!tp.containsKey("4"));
	BOOST_CHECK(!tp.containsKey("foobar"));
	BOOST_CHECK(!tp.containsKey("lalalala"));

	BOOST_CHECK(tp.containsValue(1));
	BOOST_CHECK(tp.containsValue(2));
	BOOST_CHECK(tp.containsValue(3));
	BOOST_CHECK(tp.containsValue(4));
	BOOST_CHECK(!tp.containsValue(5));
	BOOST_CHECK(!tp.containsValue(12));
	BOOST_CHECK(!tp.containsValue(65)); /*'A'*/
	BOOST_CHECK(!tp.containsValue(97)); /*'a'*/

	BOOST_CHECK(tp.size() == 4);
	BOOST_CHECK(!tp.isEmpty());

	BOOST_CHECK(tp.get("asdf") == 1);
	BOOST_CHECK(tp.get("foobar") == 0);
	BOOST_CHECK(tp.get("aspectsecurity") == 0);
	BOOST_CHECK(tp.get("fdsa") == 2);
    BOOST_CHECK(tp.get("A") == 0);
    BOOST_CHECK(tp.get("B") == 0);
    BOOST_CHECK(tp.get("C") == 0);
    BOOST_CHECK(tp.get("D") == 0);
    BOOST_CHECK(tp.get("a") == 0);
    BOOST_CHECK(tp.get("b") == 0);
    BOOST_CHECK(tp.get("c") == 0);
    BOOST_CHECK(tp.get("d") == 0);
    BOOST_CHECK(tp.get("1") == 0);
    BOOST_CHECK(tp.get("2") == 0);
    BOOST_CHECK(tp.get("3") == 0);
    BOOST_CHECK(tp.get("4") == 0);

	tp.remove("asdf");
	BOOST_CHECK(!tp.containsKey("asdf"));


	/*std::set<std::string> keys;
	std::map<std::string,int>::iterator it;
	for (it=this->map.begin(); it != this->map.end(); it++)
		keys.insert(it->first);*/


	std::set<std::string> ks = tp.keySet();

	BOOST_CHECK(tp.keySet().size() > 0);

	BOOST_CHECK(ks.size() > 0);
	BOOST_CHECK(ks.size() != 0);

	BOOST_CHECK(ks.count("fdsa") > 0);
	BOOST_CHECK(ks.find("fdsa") != ks.end());
	BOOST_CHECK(ks.find("foo") != ks.end());
	BOOST_CHECK(ks.find("bar") != ks.end());

	BOOST_CHECK(ks.find("asdf") == ks.end());
	BOOST_CHECK(ks.count("asdf") == 0);

	ks.insert("ffff");
	BOOST_CHECK(ks.count("ffff") >0);
	BOOST_CHECK(tp.get("ffff") == 0);


	std::set<int> vs = tp.values();

	BOOST_CHECK(vs.count(4) > 0);
	BOOST_CHECK(vs.count(2) > 0);
	BOOST_CHECK(vs.count(3) > 0);
	BOOST_CHECK(vs.count(5) == 0);
	BOOST_CHECK(vs.count(12) == 0);
	BOOST_CHECK(vs.count(65) == 0); /*'A'*/
	BOOST_CHECK(vs.count(97) == 0); /*'a'*/

	BOOST_CHECK(vs.find(4) != vs.end());
	BOOST_CHECK(vs.find(2) != vs.end());
	BOOST_CHECK(vs.find(3) != vs.end());
	BOOST_CHECK(vs.find(12) == vs.end());
	BOOST_CHECK(vs.find(65) == vs.end());
	BOOST_CHECK(vs.find(55) == vs.end());

	std::map<std::string,int> es = tp.entrySet();

	BOOST_CHECK(es == tp.wrapped.map);
	BOOST_CHECK(es.size() == tp.size());
	BOOST_CHECK(es.count("fdsa")>0);

	es.insert( std::pair<std::string,int>("pppp",99) );
	BOOST_CHECK(es.count("pppp") >0);
	BOOST_CHECK(!tp.containsKey("pppp")); // If it worked like Java this should fail, because the entrySet is linked to the map entries.

	/* This is how the java map is supposed to work: */
	/*std::map<std::string,int> *esp = tp.entrySet();

	esp->insert( std::pair<std::string,int>("qqqq",101) );

	BOOST_CHECK(esp->count("qqqq") >0);
	BOOST_CHECK(tp.containsKey("qqqq"));*/
}
