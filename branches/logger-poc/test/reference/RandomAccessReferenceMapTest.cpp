/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * @author jAHolmes  the.jaholmes@gmail.com
 *
 */

#include "EsapiCommon.h"

#if defined(ESAPI_OS_WINDOWS_STATIC)
// do not enable BOOST_TEST_DYN_LINK
#elif defined(ESAPI_OS_WINDOWS_DYNAMIC)
# define BOOST_TEST_DYN_LINK
#elif defined(ESAPI_OS_WINDOWS)
# error "For Windows, ESAPI_OS_WINDOWS_STATIC or ESAPI_OS_WINDOWS_DYNAMIC must be defined"
#else
# define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>
using namespace boost::unit_test;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

using esapi::Char;
using esapi::String;

#include "reference/RandomAccessReferenceMap.h"
#include "codecs/Codec.h"
#include "codecs/UnixCodec.h"
using esapi::UnixCodec;

namespace esapi
{

    BOOST_AUTO_TEST_CASE( RandRefMapTest_CtorDtor )
    {
        BOOST_MESSAGE( "Verifying RandomAccessReferenceMap class" );

        RandomAccessReferenceMap * test_ptr_obj = new RandomAccessReferenceMap();

        // just poke something to see if it's there
        String i = test_ptr_obj->getIndirectReference( String( "Marine Birds" ) );

        BOOST_CHECK_MESSAGE( i.length() == 0 , "test object was not empty" );
        
        delete test_ptr_obj;
    }

    BOOST_AUTO_TEST_CASE( RandRefMapTest_Unique )
    {
        RandomAccessReferenceMap test_obj;
        String values[ 10 ];

        for ( int i = 0; i < 10; i++ )
        {
            values[ i ] = test_obj.getUniqueReference();
        }

        for ( int i = 0; i < 10; i++ )
        {
            for ( int j = i + 1; j < 10; j++ )
            {
                BOOST_CHECK_MESSAGE( values[ i ].compare( values[ j ] ) != 0, "Duplicate value found" );
            }
        }
    }

    ////////////////
    //  In theory the other functions have already been tested via GenericAccessReferenceMapTest
    //  "In theory there is no difference between theory and practice..."
    //  Not doing full testing, 
    //  but it seems prudent to do some spot checking of operations
    //  just to make sure nothing has gone terribly wrong
    //  the type conversions for one could be causing problems 
    //
    //  that said the spot check tests are
    //  more though than they really _need_ to be thanks to the magic of cut & paste
    //  i guess that proves they weren't really required...

    BOOST_AUTO_TEST_CASE( RandomRefMapTest_AddGetRemove )
    {
        RandomAccessReferenceMap test_obj;

        String s1 = "Marine Birds";
        String s2 = "British Songbird";

        String indirect1 = test_obj.addDirectReference( s1 );
        String indirect2 = test_obj.addDirectReference( s2 );

        // because it's random we can't check 'expected' values
        // just make sure they are there, values should be tested in _unique
        BOOST_CHECK_MESSAGE( indirect1.length() > 0, "indirect string too short" );
        BOOST_CHECK_MESSAGE( indirect2.length() > 0, "indirect string too short" );

        String d1 = test_obj.getDirectReference( indirect1 );
        String d2 = test_obj.getDirectReference( indirect2 );

        BOOST_CHECK_MESSAGE( d1.compare( s1 ) == 0, "didn't get back what we put in" );
        BOOST_CHECK_MESSAGE( d2.compare( s2 ) == 0, "didn't get back what we put in" );

        String i1 = test_obj.removeDirectReference( s1 );
        BOOST_CHECK_MESSAGE( i1.compare( indirect1 ) == 0, "remove  got the wrong one" );

        String del1 = test_obj.getIndirectReference( s1 );
        BOOST_CHECK_MESSAGE( del1.length() ==  0, "entry was not removed" );

    }

    BOOST_AUTO_TEST_CASE( RandomRefMapTest_Failures )
    {
        RandomAccessReferenceMap test_obj;

        String s1 = "Felix";
        String s2 = "Garfield";

        String indirect1 = test_obj.addDirectReference( s1 );
        String indirect2 = test_obj.addDirectReference( s2 );

        BOOST_CHECK_THROW( test_obj.getDirectReference( String( "Tom" ) ), AccessControlException );

        BOOST_CHECK_THROW( test_obj.removeDirectReference( String( "Jerry" ) ), AccessControlException );
    }


    BOOST_AUTO_TEST_CASE( RandomRefMapTest_update )
    {
        String direct[4] = { "1", "2", "3", "4" };
        bool direct_seen[ 4 ];

        for ( int i = 0; i < 4; i++ )
        {
            direct_seen[ i ] = false;
        }

        std::set<String> update_set;

        update_set.insert( direct[0] );
        update_set.insert( direct[1] );
        update_set.insert( direct[2] );
        update_set.insert( direct[3] );

        RandomAccessReferenceMap test_obj;

        String i1 = test_obj.addDirectReference( "3" );

        test_obj.update( update_set );

        String u1 = test_obj.getIndirectReference( "3" );

        BOOST_CHECK_MESSAGE( i1.compare( u1 ) == 0, "Existing entry was overwritten" );


        for ( RandomAccessReferenceMap::d_iterator d_iter = test_obj.directBegin();
                d_iter != test_obj.directEnd();
                d_iter++ )
        {
            for ( int j = 0; j < 4; j++ )
            {
                if ( direct[ j ].compare( d_iter->first ) ==  0 )
                {
                    direct_seen[ j ] = true;
                }
            }
        }

        int total = 0;
        for ( int i = 0; i < 4; i++ )
        {
            total += direct_seen[ i ] ? 1 : 0;
        }

        BOOST_CHECK_MESSAGE( total == 4, "One or more items not updated" );

        update_set.clear();
    }

    BOOST_AUTO_TEST_CASE( RandomRefMapTest_iterators )
    {
        RandomAccessReferenceMap test_obj;

        String indirect[4];
        String direct[4] = { "1", "2", "3", "4" };
        bool direct_seen[ 4 ];
        bool indirect_seen[ 4 ];

        for ( int i = 0; i < 4; i++ )
        {
            direct_seen[ i ] = false;
            indirect_seen[ i ] = false;
        }

        indirect[0] = test_obj.addDirectReference( direct[ 0 ] );
        indirect[1] = test_obj.addDirectReference( direct[ 1 ] );
        indirect[2] = test_obj.addDirectReference( direct[ 2 ] );
        indirect[3] = test_obj.addDirectReference( direct[ 3 ] );

        for ( RandomAccessReferenceMap::d_iterator d_iter = test_obj.directBegin();
                d_iter != test_obj.directEnd();
                d_iter++ )
        {
            for ( int j = 0; j < 4; j++ )
            {
                if ( d_iter->first == direct[ j ] )
                {
                    direct_seen[ j ] = true;
                    if ( d_iter->second == indirect[ j ] )
                    {
                        indirect_seen[ j ] = true;
                    }
                    else
                    {
                        BOOST_ERROR( "Wrong indirect found in direct iterator" );
                    }
                }
            }
        }

        int total = 0;
        for ( int i = 0; i < 4; i++ )
        {
            total += direct_seen[ i ] ? 1 : 0;
            total += indirect_seen[ i ] ? 1: 0;
        }

        BOOST_CHECK_MESSAGE( total == 8, "One or more items not visited by direct iterator" );

        for ( int i = 0; i < 4; i++ )
        {
            direct_seen[ i ] = false;
            indirect_seen[ i ] = false;
        }

        for ( RandomAccessReferenceMap::i_iterator i_iter = test_obj.indirectBegin();
                i_iter != test_obj.indirectEnd();
                i_iter++ )
        {
            for ( int j = 0; j < 4; j++ )
            {
                if ( i_iter->first == indirect[ j ] )
                {
                    indirect_seen[ j ] = true;
                    if ( i_iter->second == direct[ j ] )
                    {
                        direct_seen[ j ] = true;
                    }
                    else
                    {
                        BOOST_ERROR( "Wrong direct found in indirect iterator" );
                    }
                }
            }
        }

        total = 0;
        for ( int i = 0; i < 4; i++ )
        {
            total += direct_seen[ i ] ? 1 : 0;
            total += indirect_seen[ i ] ? 1: 0;
        }

        BOOST_CHECK_MESSAGE( total == 8, "One or more items not visited by indirect iterator" );

    }

}


