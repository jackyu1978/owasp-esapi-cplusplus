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
#include <exception>

#include <sstream>
using std::stringstream;
using std::istringstream;
using std::ostringstream;

#include "reference/validation/StringValidationRule.h"


BOOST_AUTO_TEST_CASE( StringValidationRuleTestCase )
{

	BOOST_CHECK(true);
	//BOOST_CHECK_THROW( throw new std::exception, std::exception);
}
