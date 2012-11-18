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

#include "reference/GenericAccessReferenceMap.h"
#include "codecs/Codec.h"
#include "codecs/UnixCodec.h"
using esapi::UnixCodec;
using esapi::GenericAccessReferenceMap;


using std::shared_ptr;


namespace esapi
{

    /** *********
     *  Instantiate a concrete class based on the generic abstract class for testing
     */
    class ESAPI_EXPORT TestGenericAccessReferenceMap : public GenericAccessReferenceMap< int, int >
    {
    public:

        TestGenericAccessReferenceMap() 
        { 
            count = 200; 
        }

        virtual int getUniqueReference()
        {
            return count++;
        }


        virtual ~TestGenericAccessReferenceMap() {};

        int count;

    };


    BOOST_AUTO_TEST_CASE( GenericRefMapTest_CTORDTOR )
    {
        BOOST_MESSAGE( "Verifying GenericAccessReferenceMap class" );

        TestGenericAccessReferenceMap * test_ptr_obj = new TestGenericAccessReferenceMap();

        // object created, good start
        BOOST_CHECK_MESSAGE( test_ptr_obj != NULL,  "Ctor failed to created object" );

        // internal var has been set so ctor must have run correctly
        BOOST_CHECK_MESSAGE( test_ptr_obj->count == 200, "Ctor init private var" );
        
        // if dtor doesn't run, we will have a memory leak
        delete test_ptr_obj;
    }

    BOOST_AUTO_TEST_CASE( GenericRefMapTest_AddGetRemove )
    {
        TestGenericAccessReferenceMap test_obj;

        int i1 = test_obj.addDirectReference( 1 );
        int i2 = test_obj.addDirectReference( 2 );
        int i3 = test_obj.addDirectReference( 3 );
        int i4 = test_obj.addDirectReference( 4 );

        BOOST_CHECK_MESSAGE( i1 == 200, " indirect value not 200" );
        BOOST_CHECK_MESSAGE( i2 == 201, " indirect value not 201" );
        BOOST_CHECK_MESSAGE( i3 == 202, " indirect value not 202" );
        BOOST_CHECK_MESSAGE( i4 == 203, " indirect value not 203" );

        int fi1 = test_obj.getIndirectReference( 1 );
        int fi2 = test_obj.getIndirectReference( 2 );
        int fi3 = test_obj.getIndirectReference( 3 );
        int fi4 = test_obj.getIndirectReference( 4 );

        BOOST_CHECK_MESSAGE( i1 == fi1, " indirect value in fi1" );
        BOOST_CHECK_MESSAGE( i2 == fi2, " indirect value in fi2" );
        BOOST_CHECK_MESSAGE( i3 == fi3, " indirect value in fi3" );
        BOOST_CHECK_MESSAGE( i4 == fi4, " indirect value in fi4" );

        int d1 = test_obj.getDirectReference( i1 );
        int d2 = test_obj.getDirectReference( i2 );
        int d3 = test_obj.getDirectReference( i3 );
        int d4 = test_obj.getDirectReference( i4 );

        BOOST_CHECK_MESSAGE( d1 == 1, " direct value not 1" );
        BOOST_CHECK_MESSAGE( d2 == 2, " direct value not 2" );
        BOOST_CHECK_MESSAGE( d3 == 3, " direct value not 3" );
        BOOST_CHECK_MESSAGE( d4 == 4, " direct value not 4" );

        int r1 = test_obj.removeDirectReference( 1 );
        BOOST_CHECK_MESSAGE( r1 == 200, " indirect value not 200" );
        int pr1 = test_obj.getIndirectReference( 1 );
        BOOST_CHECK_MESSAGE( pr1 == 0, " direct value 1 not removed" );

        int r2 = test_obj.removeDirectReference( 2 );
        BOOST_CHECK_MESSAGE( r2 == 201, " indirect value not 201" );
        int pr2 = test_obj.getIndirectReference( 2 );
        BOOST_CHECK_MESSAGE( pr2 == 0, " direct value 2 not removed" );

        int r3 = test_obj.removeDirectReference( 3 );
        BOOST_CHECK_MESSAGE( r3 == 202, " indirect value not 202" );
        int pr3 = test_obj.getIndirectReference( 3 );
        BOOST_CHECK_MESSAGE( pr3 == 0, " direct value 3 not removed" );

        int r4 = test_obj.removeDirectReference( 4 );
        BOOST_CHECK_MESSAGE( r4 == 203, " indirect value not 203" );
        int pr4 = test_obj.getIndirectReference( 4 );
        BOOST_CHECK_MESSAGE( pr4 == 0, " direct value 4 not removed" );

    }

    BOOST_AUTO_TEST_CASE( GenericRefMapTest_RemoveFailure )
    {
        TestGenericAccessReferenceMap test_obj;

        int i1 = test_obj.addDirectReference( 1 );

        // bad remove
        BOOST_CHECK_THROW( test_obj.removeDirectReference( 111 ), AccessControlException );

        // good remove still works
        BOOST_CHECK_NO_THROW( test_obj.removeDirectReference( 1 ) );
    }

    BOOST_AUTO_TEST_CASE( GenericRefMapTest_GetDirectFailure )
    {
        TestGenericAccessReferenceMap test_obj;

        int i1 = test_obj.addDirectReference( 7 );

        // bad get
        BOOST_CHECK_THROW( test_obj.getDirectReference( i1 + 20 ), AccessControlException );

        // good get still works
        int direct_value;
        BOOST_CHECK_NO_THROW( direct_value = test_obj.getDirectReference( i1 ) );

        BOOST_CHECK_MESSAGE( 7 == direct_value, "Wrong direct returned" );
    }

    BOOST_AUTO_TEST_CASE( GenericRefMapTest_UniqueReference )
    {
        TestGenericAccessReferenceMap test_obj;
        int values[ 10 ];

        for ( int i = 0; i < 10; i++ )
        {
            values[ i ] = test_obj.getUniqueReference();
        }

        for ( int i = 0; i < 10; i++ )
        {
            for ( int j = i + 1; j < 10; j++ )
            {
                BOOST_CHECK_MESSAGE( values[ i ] != values[ j ], "Duplicate value found" );
            }
        }
    }

    BOOST_AUTO_TEST_CASE( GenericRefMapTest_iterators )
    {
        TestGenericAccessReferenceMap test_obj;

        int indirect[4];
        int direct[4] = { 1,2,3,4 };
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

        for ( TestGenericAccessReferenceMap::d_iterator d_iter = test_obj.directBegin();
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

        for ( TestGenericAccessReferenceMap::i_iterator i_iter = test_obj.indirectBegin();
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

    BOOST_AUTO_TEST_CASE( GenericRefMapTest_update )
    {
        int direct[4] = { 1,2,3,4 };
        bool direct_seen[ 4 ];

        for ( int i = 0; i < 4; i++ )
        {
            direct_seen[ i ] = false;
        }

        std::set<int> update_set;

        update_set.insert( direct[0] );
        update_set.insert( direct[1] );
        update_set.insert( direct[2] );
        update_set.insert( direct[3] );

        TestGenericAccessReferenceMap test_obj;

        int i1 = test_obj.addDirectReference( 3 );

        test_obj.update( update_set );

        int u1 = test_obj.getIndirectReference( 3 );

        BOOST_CHECK_MESSAGE( i1 == u1, "Existing entry was overwritten" );


        for ( TestGenericAccessReferenceMap::d_iterator d_iter = test_obj.directBegin();
                d_iter != test_obj.directEnd();
                d_iter++ )
        {
            for ( int j = 0; j < 4; j++ )
            {
                if ( d_iter->first == direct[ j ] )
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

}

