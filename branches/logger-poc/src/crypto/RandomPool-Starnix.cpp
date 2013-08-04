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

#include "crypto/RandomPool.h"
#include "util/ArrayZeroizer.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"

#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#if defined(ESAPI_OS_LINUX)
# include <sys/ioctl.h>
# include <linux/random.h>
#endif

namespace esapi
{
  // Helper to automatically close a file descriptor
  class AutoFileDesc
  {
  public:
    explicit AutoFileDesc(int& fd) : m_fd(fd) { }

    ~AutoFileDesc() {
      if(m_fd) {
        close(m_fd);
        m_fd = -1;
      }
    }

  private:
    int m_fd;
  };

#if defined(ESAPI_OS_LINUX) && defined(ESAPI_CXX_GCC) && (defined(ESAPI_ARCH_X86) || defined(ESAPI_ARCH_X64))
  // Shamelessy ripped from somehwere.
  static __inline__ unsigned long long rdtsc(void)
  {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((((unsigned long long)hi) << 32) | (unsigned long long)lo);
  }
#endif

  /**
   * Fetches time data, encrypts the time data under the key and iv selected earlier.
   * The key is being constructed for the RandomPool's AES256 cipher. Since we also
   * sync an IV, at least 48 bytes will be needed.
   */
  bool RandomPool::GenerateKeyAndIv(byte* key, size_t ksize)
  {
    ASSERT(key && ksize);
    if(!key || !ksize) return false;

    size_t  rem /*remaining*/ = ksize;
    size_t  idx = 0;
    ssize_t ret  = 0;

    // First try /dev/random
    {
      do
        {
          int fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
          AutoFileDesc z1(fd);

          ESAPI_ASSERT2(fd > 0, "Failed to open /dev/random");
          if( !(fd > 0) ) break; /* Failed */

          ret = read(fd, key+idx, rem);
          ESAPI_ASSERT2(ret > 0, "Failed to read from /dev/random");
          ESAPI_ASSERT2(ret == (ssize_t)rem, "Failed to read entire chunk from /dev/random");
            
          if(ret > 0) {
            rem -= (size_t)ret;
            idx += (size_t)ret;
          }
            
        } while(false);
    }

    // Early out if possible.
    if(rem == 0) return true;

    // Next try /dev/urandom
    {
      do
        {
          int fd = open("/dev/urandom", O_RDONLY | O_NONBLOCK);
          AutoFileDesc z1(fd);

          ESAPI_ASSERT2(fd > 0, "Failed to open /dev/urandom");
          if( !(fd > 0) ) break; /* Failed */

          ret = read(fd, key+idx, rem);
          ESAPI_ASSERT2(ret > 0, "Failed to read from /dev/urandom");
          ESAPI_ASSERT2(ret == (ssize_t)rem, "Failed to read entire chunk from /dev/urandom");

          if(ret > 0)
            rem -= (size_t)ret;

        } while(false);
    }

    return (rem == 0);
  }

  /**
   * Fetches time related data. The time data is a value from a
   * high resolution timer and the standard time of day. We are
   * intersted in the high performance counter since it is helpful
   * in a virtual environment where rollbacks may occur.
   */
  bool RandomPool::GetTimeData(byte* data, size_t dsize)
  {
    ASSERT(data && dsize);
    if(!data || !dsize) return false;

    size_t idx = 0, rem = dsize, req = 0;

#if defined(ESAPI_OS_LINUX) && defined(ESAPI_CXX_GCC) && (defined(ESAPI_ARCH_X86) || defined(ESAPI_ARCH_X64))
    unsigned long long ts = rdtsc();

    req = std::min(rem, sizeof(ts));
    ::memcpy(data, &ts, req);
    rem -= req; idx+= req;

    // Any room remaining? There should be...
    if(!rem) return true;
#endif

    time_t now;
    time(&now);

    req = std::min(rem, sizeof(now));
    ::memcpy(data+idx, &now, req);

    return true;
  }
}

