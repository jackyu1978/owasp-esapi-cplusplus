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
#pragma once

#include "EsapiCommon.h"
#include "util/Mutex.h"
#include "util/NotCopyable.h"
#include "crypto/Crypto++Common.h"

namespace esapi
{
  /**
  * This class has no corresponding Java implementation. It is used to fetch
  * entropy from the Operating System for use in/by SecureRandom.
  *
  * A single instance of the Random Pool exists. Upon startup, the pool will
  * attempt to read from /dev/random if the bytes are available. If not
  * available, the pool will attempt to read from /dev/urandom. If not available
  * the pool will latch a [temporary] error condition.
  *
  * If SecureRandom attempts read bytes while in an error condition, the pool
  * will attempt to clear the error by seeding as described above. If the pool
  * is not able to clear the condition, the pool will throw during the call.
  *
  * Once the pool acquires bytes, the pool will hash the data using SHA-512. The
  * hashed data will be used to key an instance of AES-256/OFB. When SecureRandom
  * fetches bytes from the pool, time data is encrypted under the key. The time data
  * consists of the pair {Performance Counter||GetTimeOfDay}. As output blocks are
  * created, the blocks are used fulfill the request for bytes. In addition, the
  * block is fed back into the system for the next encryption operation.
  *
  * Analysis: since this system uses AES-256/OFB, it is no less secure than the raw
  * entropy bits retrieved from the operating system. That is, generating a stream
  * using AES-256/OFB (keyed with /dev/[u]random) is *not* less secure than using
  * /dev/[u]random directly.
  */
  class RandomPool : public NotCopyable
  {
  public:
    /**
    * Retrieve the shared copy of the random pool.
    */
    static RandomPool& GetSharedInstance();

    /**
    * Retrieve bytes form the random pool.
    */
    void GenerateBlock(byte* bytes, size_t size);

    /**
    * Reseed the random pool.
    */
    void Reseed();

  public:
    /**
    * Destroy the random pool.
    */
    ~RandomPool();

  private:
    /**
    * Create a random pool. Users must call GetSharedInstance().
    */
    RandomPool();

    /**
    * Initializes the random pool by setting a key and IV from OS acquired entropy.
    */
    bool Rekey();

    /**
    * Acquires entropy from the pool, runs it through SHA-512, fetches
    * time data (via GetTimeData), and creates the key and IV for the cipher.
    */
    bool GenerateKey(byte* key, size_t ksize);

    /**
    * Fetches time related data. The time data is a value from a
    * high resolution timer and the standard time of day.
    */
    bool GetTimeData(byte* data, size_t dsize);

  private:
    /**
    * A lock for the internal operations. Its static because GetSharedIntstance()
    * serves up a single static object. Before the first construction of thew static
    * object, the lock is acquired.
    */
    static Mutex& GetSharedLock();

    /**
    * Keying status.
    */
    bool m_keyed;

    /**
    * Crypto++ cipher.
    */
    CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption m_cipher;
  };
}
