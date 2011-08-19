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

#include "EsapiCommon.h"
#include "util/Mutex.h"

#include <string>
#include <sstream>
#include <stdexcept>

#include <errno.h>

namespace esapi
{
    Mutex::Mutex()
  {
#if defined(ESAPI_OS_WINDOWS)
    InitializeCriticalSection(&m_primitive);
#elif defined(ESAPI_OS_STARNIX )
    int ret = pthread_mutex_init(&m_primitive, NULL);
    ASSERT(ret == 0);
    if(ret != 0)
      {
        std::ostringstream oss;
        oss << "Failed to intialize mutex, error = " << errno << ".";
        throw std::runtime_error(oss.str());
      }
#endif
  }

  Mutex::~Mutex()
  {
#if defined(ESAPI_OS_WINDOWS)
    DeleteCriticalSection(&m_primitive);
#elif defined(ESAPI_OS_STARNIX)
    int ret = pthread_mutex_destroy(&m_primitive);
    // ASSERT, but don't throw
    ASSERT(ret == 0);
#endif
  }

  LockPrimitive& Mutex::getMutex()
  {
    return m_primitive;
  }

  MutexAutoLock::MutexAutoLock(Mutex& mutex)
    : m_mutex(mutex)
  {
#if defined(ESAPI_OS_WINDOWS)
    EnterCriticalSection(&m_mutex.getMutex());
#elif defined(ESAPI_OS_STARNIX)
    int ret = pthread_mutex_lock(&m_mutex.getMutex());
    ASSERT(ret == 0);
    if(ret != 0)
      {
        std::ostringstream oss;
        oss << "Failed to acquire mutex, error = " << errno << ".";
        throw std::runtime_error(oss.str());
      }
#endif
  }

  MutexAutoLock::~MutexAutoLock()
  {
#if defined(ESAPI_OS_WINDOWS)
    LeaveCriticalSection(&m_mutex.getMutex());
#elif defined(ESAPI_OS_STARNIX)
    int ret = pthread_mutex_unlock(&m_mutex.getMutex());
    ASSERT(ret == 0);
    if(ret != 0)
      {
        std::ostringstream oss;
        oss << "Failed to acquire mutex, error = " << errno << ".";
        throw std::runtime_error(oss.str());
      }
#endif
  }

} // esapi
