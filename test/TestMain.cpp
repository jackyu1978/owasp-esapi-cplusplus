/*
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* http://www.owasp.org/index.php/ESAPI.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* @author Kevin Wall, kevin.w.wall@gmail.com
* @author Jeffrey Walton, noloader@gmail.com
*
*/

/**
 *
 * Compile for testing:
 * g++ -DDEBUG -O0 -g3 -ggdb TestMain.cpp -o TestMain.exe -L ../lib -lesapi-c++
 *
 **/

#if defined(_WIN32)
    #if defined(STATIC_TEST)
        // do not enable BOOST_TEST_DYN_LINK
    #elif defined(DLL_TEST)
        #define BOOST_TEST_DYN_LINK
    #else
        #error "For Windows you must define either STATIC_TEST or DLL_TEST"
    #endif
#else
    #define BOOST_TEST_DYN_LINK
#endif
#define BOOST_TEST_MODULE "ESAPI C++ Unit Tests"
#include <boost/test/unit_test.hpp>

/*
int main(int argc, char** argv)
{
    
    return 0;
}
*/
