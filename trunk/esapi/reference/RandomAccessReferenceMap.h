/**
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

#pragma once

#include <string>

#include "EsapiCommon.h"
#include "EsapiTypes.h"
#include "reference/GenericAccessReferenceMap.h"

namespace esapi
{

    /**
     *  provides a codeword in place of a number for the indirect string
     */
    template < typename D >
    class ESAPI_EXPORT RandomAccessGenericReferenceMap : public GenericAccessReferenceMap< String, D >
    {
    public:

        /**
         * CTOR
         */
        RandomAccessGenericReferenceMap()
        {
            // !WORKAROUND!  2012.03.01 jAHOLMES
            // replace this with the appropriate call when esapi::randomize() is available
            srand( (unsigned)time( NULL ) );
        }

        /**
         * gets a string of randomw letters, 
         * makes sure it doesn't match ones already in use in this instance
         * @return  a string of random letters
         */
        virtual String getUniqueReference()
        {
            boost::lock_guard<boost::mutex>  lock( lockCounter );

            // typename std::map<String,D>::iterator iter;
            String candidate;
            do
            {      
                candidate = FetchRandomString();
            }
            while ( GenericAccessReferenceMap< String, D >::itod->find(candidate) != GenericAccessReferenceMap< String, D >::itod->end() );

            return candidate;
        }

        /**
         * DTOR
         */
        virtual ~RandomAccessGenericReferenceMap() {};

    private:

        /**
         *  wrapper function for the random string function
         */
        String FetchRandomString()
        {
            // !WORKAROUND!  2012.03.01 jAHOLMES
            // the commented line is what we are suppose to be using, but
            // as of 2012.03.01 someone else is still working on writing the random functions

#pragma message( "Need to install correct randomizer() when it is ready" )
            // return esapi::randomizer().getRandomString( 6, EncoderConstants.CHAR_ALPHANUMERICS );

            // temporary
            String letters = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            String sb;

            for ( int i = 0; i < 6; i++ )
            {
                int r = rand() % 26;
                sb +=  letters.substr( r, 1 );
            }

            return sb;
        }

        /**
         *  synchronize string generation
         */
        boost::mutex  lockCounter;
    };

    /**
     * name the commonly used version for ease of use
     */
    typedef  RandomAccessGenericReferenceMap< String > RandomAccessReferenceMap;
} // NAMESPACE

