/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/index.php/ESAPI.
 *
 * Copyright (c) 2012 - The OWASP Foundation
 */

#pragma once

#include "errors/AccessControlException.h"

#include <set>
#include <map>

#include <boost/thread.hpp>

#include "AccessReferenceMap.h"

namespace esapi
{

/**
 * The AccessReferenceMap interface is used to map from a set of internal
 * direct object references to a set of indirect references that are safe to
 * disclose publicly. This can be used to help protect database keys,
 * filenames, and other types of direct object references. As a rule, developers
 * should not expose their direct object references as it enables attackers to
 * attempt to manipulate them.
 * <p>
 * Indirect references are handled as strings, to facilitate their use in HTML.
 * Implementations can generate simple integers or more complicated random
 * character strings as indirect references. Implementations should probably add
 * a constructor that takes a list of direct references.
 * <p>
 * Note that in addition to defeating all forms of parameter tampering attacks,
 * there is a side benefit of the AccessReferenceMap. Using random strings as indirect object
 * references, as opposed to simple integers makes it impossible for an attacker to
 * guess valid identifiers. So if per-user AccessReferenceMaps are used, then request
 * forgery (CSRF) attacks will also be prevented.
 *
 * <pre>
 * Set fileSet = new HashSet();
 * fileSet.addAll(...); // add direct references (e.g. File objects)
 * AccessReferenceMap map = new AccessReferenceMap( fileSet );
 * // store the map somewhere safe - like the session!
 * String indRef = map.getIndirectReference( file1 );
 * String href = &quot;http://www.aspectsecurity.com/esapi?file=&quot; + indRef );
 * ...
 * // if the indirect reference doesn't exist, it's likely an attack
 * // getDirectReference throws an AccessControlException
 * // you should handle as appropriate
 * String indref = request.getParameter( &quot;file&quot; );
 * File file = (File)map.getDirectReference( indref );
 * </pre>
 *
 * <p>
 *
  * <hr/>
 *  Variations from original Java Implementation
 *  <p> 
 *  Java iterators work significantly differently from the STL idiom,
 *  but the desire here was to be C++ friendly rather than platform neutral
 *  so the iterator function was given a makeover to fit the STL idiom.
 * <p>
 *  Likewise, Java has thread and locking awareness built-in to its 
 *  collection classes, so that had to be added seperately.
 * <p>
 *  Other than those changes, this follows the Java implementations as closely as I could.
 *  A suggestion was made that the Boost::bimap could have been used instead of two maps.
 * <p>
 * follows Java implementation by @author Chris Schmidt (chrisisbeef@gmail.com)
 * @author Jeffrey Holmes (the.jaholmes@gmail.com)
 */

    template<typename I, typename D>
    class ESAPI_EXPORT GenericAccessReferenceMap : public AccessReferenceMap<I,D>
	{
	public:

        /**
         * rename template iterator for ease of use
         */
        typedef typename std::map<I,D>::iterator  i_iterator;
        typedef typename std::map<D,I>::iterator  d_iterator;

        /**
         *  Default ctor
         */
        GenericAccessReferenceMap()  
        {
            itod = new std::map<I,D>();
            dtoi = new std::map<D,I>();
        }

        /**
         * default dtor
         */
        ~GenericAccessReferenceMap()
        {
            {
                boost::lock_guard<boost::mutex>  lock( lockMaps );

                if ( itod != NULL )
                { 
                    delete itod;
                    itod = NULL;
                }

                if ( dtoi != NULL )
                {
                    delete dtoi;
                    dtoi = NULL;
                }
            }
        }

        /**
         * fetch the indirect reference that matches the supplied direct reference
         *
         * @param directReference to look up
         * @return the indirect reference, 
         *      or default value of type I if the direct reference does not exist
         */
        I getIndirectReference( D directReference )
        {
            boost::lock_guard<boost::mutex>  lock( lockMaps );

            d_iterator itr = dtoi->find( directReference );

            I i_ref = I();
            if ( itr != dtoi->end() )
            {
              i_ref = itr->second;
            }

            return i_ref;
        }

        /**
         * fetch the direct reference that matches the supplied indirect reference
         *
         * @param indirectReference to look up
         * @return the direct reference 
         * @throws AccessControlException if the input is not in the collection 
         *         or cannot be cast to the approprite type
         */
        D getDirectReference(I indirectReference)
        {
            boost::lock_guard<boost::mutex>  lock( lockMaps );

            i_iterator i = itod->find( indirectReference );
            
            if ( i != itod->end() )
            {
                return ( i->second );
            }
            else
            {
                throw AccessControlException(
                                NarrowString( "Access denied" ), 
                                NarrowString( "Request for invalid direct reference." ) );
            }
        }

        /**
         * insert a new direct reference (old ones accepted silently)
         * @param direct the new direct reference
         * @return the corresponding indirect reference
         */
        I addDirectReference(D direct)
        {
            boost::lock_guard<boost::mutex>  lock( lockMaps );

            d_iterator i = dtoi->find( direct );
            if ( i != dtoi->end() ) 
            {
                return ( i->second );
            }
            I indirect = getUniqueReference();
            itod->insert( std::pair<I,D>( indirect, direct ) );
            dtoi->insert( std::pair<D,I>( direct, indirect ) );
            return indirect;
        }

        /**
         * removes the specified direct reference form the catalog
         * @param direct the direct reference to remove
         * @returns the associated indirect reference
         * @throws AccessControlException if the direct reference does not exist
         */
        I removeDirectReference(D direct)
        {
            boost::lock_guard<boost::mutex>  lock( lockMaps );

            d_iterator i = dtoi->find( direct );
            I indirect;
            if ( i != dtoi->end() ) 
            {
                indirect = i->second;
                itod->erase( indirect );
                dtoi->erase( direct );
            }
            else
            {
                throw AccessControlException(
                                NarrowString( "Access denied" ), 
                                NarrowString( "Request to remove invalid direct reference." ) );
            }
            return ( indirect );
        }

        /**
         * replaces a set of direct references with a new set,
         * if the new set overlaps the old set, the corresponding indirect references will be preserved
         * @param directReferences  the set of new references
         */
        void update(std::set<D>& directReferences)
        {
            boost::lock_guard<boost::mutex>  lock( lockMaps );

            std::map<I,D> * new_itod = new std::map<I,D>( );
            std::map<D,I> * new_dtoi = new std::map<D,I>( );

            for ( typename std::set<D>::iterator s_iter = directReferences.begin(); s_iter != directReferences.end(); s_iter++ )
            {
                I indirect;
                d_iterator i_iter = dtoi->find( *s_iter );
                if ( i_iter != dtoi->end() )
                {
                    indirect = i_iter->second;
                }
                else
                {
                    indirect = getUniqueReference();
                }

                 new_itod->insert( std::pair<I,D>( indirect, *s_iter ) );
                 new_dtoi->insert( std::pair<D,I>( *s_iter, indirect ) );
            }
            delete dtoi;
            delete itod;

            dtoi = new_dtoi;
            itod = new_itod;
        }

        /**
         * creates a unique reference 
         */
        virtual I getUniqueReference() = 0;

        /**
         *  obtains an starting point iterator for the indirect catalog
         */
        virtual inline i_iterator indirectBegin()
        {
            if ( itod == NULL )
            {
                return (i_iterator)NULL;
            }
            else
            {
                return itod->begin();
            }
        }

        /**
         * obtains the iterator end point for the indirect catalog
         */
        virtual inline i_iterator indirectEnd()
        {
            if ( itod == NULL )
            {
                return (i_iterator)NULL;
            }
            else
            {
                return itod->end();
            }
        }

        /**
         *  obtains an starting point iterator for the direct catalog
         */
        virtual inline d_iterator directBegin()
        {
            if ( dtoi == NULL )
            {
                return (d_iterator)NULL;
            }
            else
            {
                return dtoi->begin();
            }
        }

        /**
         * obtains the iterator end point for the direct catalog
         */
        virtual inline d_iterator directEnd()
        {
            if ( dtoi == NULL )
            {
                return (d_iterator)NULL;
            }
            else
            {
                return dtoi->end();
            }
        }

    protected:
        
        /**
         *  holder for the indirect to direct mapping
         */
        std::map<I,D>  * itod;

        /**
         * holder for the direct to indirect mapping
         */
        std::map<D,I>  * dtoi;

        /**
         * used to porvide synchronization of map access
         */
        boost::mutex  lockMaps;

    };

}
