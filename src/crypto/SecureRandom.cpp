/**
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

#include "crypto/SecureRandom.h"
#include "util/AlgorithmName.h"
#include "crypto/SecureRandomImpl.h"
#include "safeint/SafeInt3.hpp"

#include <algorithm>

/**
 * This class implements functionality similar to Java's SecureRandom for consistency
 * http://download.oracle.com/javase/6/docs/api/java/security/SecureRandom.html
 */
namespace esapi
{
    /**
     * The default secure random number generator (RNG) algorithm. Currently returns
     * SHA-256. SHA-1 is approved for Random Number Generation. See SP 800-57, Table 2.
     */
    NarrowString SecureRandom::DefaultAlgorithm()
    {
        return NarrowString("SHA-256");
    }

    /**
     * Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
     */
    SecureRandom SecureRandom::getInstance(const NarrowString& algorithm)
    {
        ASSERT( !algorithm.empty() );

        const NarrowString alg(AlgorithmName::normalizeAlgorithm(algorithm));
        SecureRandomBase* impl = SecureRandomBase::createInstance(alg, nullptr, 0);
        MEMORY_BARRIER();

        ASSERT(impl != nullptr);
        return SecureRandom(impl);
    }

    /**
     * Returns a SecureRandom object that implements the specified Random Number Generator (RNG) algorithm.
     */
    SecureRandom SecureRandom::getInstance(const WideString& algorithm)   
    {
        ASSERT( !algorithm.empty() );
        return getInstance(TextConvert::WideToNarrow(algorithm));
    }

    /**
     * Constructs a secure random number generator (RNG) implementing the named
     * random number algorithm if specified
     */
    SecureRandom::SecureRandom(const NarrowString& algorithm)   
        : m_lock(new Mutex),
          m_impl(SecureRandomBase::createInstance(AlgorithmName::normalizeAlgorithm(algorithm), nullptr, 0))    
    {
        ASSERT( !algorithm.empty() );
        ASSERT(m_lock.get() != nullptr);
        ASSERT(m_impl.get() != nullptr);
    }

    /**
     * Constructs a secure random number generator (RNG) implementing the named
     * random number algorithm if specified
     */
    SecureRandom::SecureRandom(const WideString& algorithm)   
        : m_lock(new Mutex),
          m_impl(SecureRandomBase::createInstance(TextConvert::WideToNarrow(AlgorithmName::normalizeAlgorithm(algorithm)), nullptr, 0))
    {
        ASSERT( !algorithm.empty() );
        ASSERT(m_lock.get() != nullptr);
        ASSERT(m_impl.get() != nullptr);
    }

    /**
     * Constructs a secure random number generator (RNG) implementing the default random number algorithm.
     */
    SecureRandom::SecureRandom(const byte seed[], size_t size)  
        : m_lock(new Mutex), m_impl(SecureRandomBase::createInstance(DefaultAlgorithm(), seed, size))
    {
        ASSERT(m_lock.get() != nullptr);
        ASSERT(m_impl.get() != nullptr);
    }

    /**
     * Constructs a secure random number generator (RNG) from a SecureRandomBase implementation.
     */
    SecureRandom::SecureRandom(SecureRandomBase* impl)   
        : m_lock(new Mutex), m_impl(impl)
    {
        ASSERT(impl);
        ASSERT(m_lock.get() != nullptr);
        ASSERT(m_impl.get() != nullptr);
    }

    /**
     * Copy this secure random number generator (RNG).
     */
    SecureRandom::SecureRandom(const SecureRandom& rhs)
        : m_lock(rhs.m_lock), m_impl(rhs.m_impl)
    {
        ASSERT(m_lock.get() != nullptr);
        ASSERT(m_impl.get() != nullptr);
    }

    /**
     * Assign this secure random number generator (RNG).
     */
    SecureRandom& SecureRandom::operator=(const SecureRandom& rhs)
    {
        // Need to think about this one.... We want to lock 'this' in case
        // someone else is using it. However, MutexLock takes a reference
        // to 'this' object's lock. After the assignment below, the lock
        // has changed (it points to the new object lock). We subsequently
        // release the new lock (not the old lock).
        //std::shared_ptr<Mutex> tlock(m_lock);
        //ASSERT(tlock.get() != nullptr);
        //MutexLock lock(*tlock.get());

        if(this != &rhs)
        {
            m_lock = rhs.m_lock;
            m_impl = rhs.m_impl;
        }

        ASSERT(m_lock.get() != nullptr);
        ASSERT(m_impl.get() != nullptr);

        return *this;
    }

    /**
     * Retrieves the object level lock
     */
    Mutex& SecureRandom::getObjectLock() const
    {
        ASSERT(m_lock.get());
        return *m_lock.get();
    }

    /**
     * Returns the given number of seed bytes, computed using the seed generation algorithm that this class uses to seed itself.
     */
    SecureByteArray SecureRandom::generateSeed(unsigned int numBytes)   
    {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexLock lock(getObjectLock());

        ASSERT(m_impl.get() != nullptr);
        return m_impl->generateSeedImpl(numBytes);
    }

    /**
     * Returns the name of the algorithm implemented by this SecureRandom object.
     */
    NarrowString SecureRandom::getAlgorithm() const   
    {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexLock lock(getObjectLock());

        ASSERT(m_impl.get() != nullptr);
        return m_impl->getAlgorithmImpl();
    }  

    /**
     * Returns the security level associated with the SecureRandom object. Used
     * by KeyGenerator to determine the appropriate key size for init.
     */
    unsigned int SecureRandom::getSecurityLevel() const   
    {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexLock lock(getObjectLock());

        ASSERT(m_impl.get() != nullptr);
        return m_impl->getSecurityLevelImpl();
    }

    /**
     * Generates a user-specified number of random bytes.
     */
    void SecureRandom::nextBytes(byte bytes[], size_t size)   
    {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexLock lock(getObjectLock());

        ASSERT(m_impl.get() != nullptr);
        m_impl->nextBytesImpl(bytes, size);
    }

    /**
     * Reseeds this random object.
     */
    void SecureRandom::setSeed(const byte seed[], size_t size)   
    {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexLock lock(getObjectLock());

        // No need to lock RandomPool - it provides its own
        RandomPool::GetSharedInstance().Reseed();

        // Reseed the SecureRandom object
        ASSERT(m_impl.get() != nullptr);
        m_impl->setSeedImpl(seed, size);
    }

    /**
     * Reseeds this random object, using the bytes contained in the given long seed.
     */
    void SecureRandom::setSeed(int seed)   
    {
        // All forward facing gear which manipulates internal state acquires the object lock
        MutexLock lock(getObjectLock());

        ASSERT(m_impl.get() != nullptr);
        m_impl->setSeedImpl((const byte*)&seed, sizeof(seed));
    }

} // esapi
