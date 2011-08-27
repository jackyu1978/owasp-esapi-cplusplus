/*
* OWASP Enterprise Security API (ESAPI)
*
* This file is part of the Open Web Application Security Project (OWASP)
* Enterprise Security API (ESAPI) project. For details, please see
* <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
*
* Copyright (c) 2011 - The OWASP Foundation
*
* @author Kevin Wall, kevin.w.wall@gmail.com
* @author Jeffrey Walton, noloader@gmail.com
*/

#pragma once

#include "EsapiCommon.h"

#if defined(ESAPI_OS_WINDOWS)
# include <windows.h>
typedef CRITICAL_SECTION LockPrimitive;
#elif defined(ESAPI_OS_STARNIX)
# include <pthread.h>
typedef pthread_mutex_t LockPrimitive;
#else
# error "Unsupported Operating System"
#endif

namespace esapi
{
  class MutexLock;

  class ESAPI_EXPORT Mutex
  {
  public:
    explicit Mutex();
    virtual ~Mutex();

    LockPrimitive& getMutex();

  private:
    LockPrimitive m_primitive;
  };

  class ESAPI_EXPORT MutexLock
  {
  public:
    explicit MutexLock(Mutex& mutex);
    virtual ~MutexLock();

  private:
    Mutex& m_mutex;

  private:
    MutexLock& operator=(const MutexLock&);
  };
}
