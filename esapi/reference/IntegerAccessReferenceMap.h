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

#include "EsapiCommon.h"
#include "reference/GenericAccessReferenceMap.h"

namespace esapi
{

    /**
     * implements the incrementing integer version of the reference map
     */
    template < typename D >
    class ESAPI_EXPORT IntegerAccessGenericReferenceMap : public GenericAccessReferenceMap< String, D >
    {
    public:

        /**
         *  CTOR
         */
        IntegerAccessGenericReferenceMap()  
        {
            // let zero be optionally reserved for bad values
            count = 1;
        }

        /**
         * the unique value for an integer is a incrementing count
         *
         * @return the next token as a string
         */
        virtual String getUniqueReference()
        {
            boost::lock_guard<boost::mutex>  lock( lockCounter );
#if  ESAPI_OS_WINDOWS
            TCHAR buffer[ 64 ];
            swprintf_s( buffer, 64, L"%d", count++ );

            return String( buffer );
#else
            StringStream ss;
            ss << count++;

            return ss.str();
#endif
        }

        /**
         *  DTOR
         */
        virtual ~IntegerAccessGenericReferenceMap() {};

    private:

        /**
         *  tracks requests to provide unique per instance  reference numbers
         */
        int count;

        /**
         * thread protect the counter increment
         */
        boost::mutex  lockCounter;
    };

    /**
     * name the commonly used version for ease of use
     */
    typedef IntegerAccessGenericReferenceMap< String > IntegerAccessReferenceMap;
};

