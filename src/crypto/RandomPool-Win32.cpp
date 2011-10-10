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
#include "crypto/Crypto++Common.h"
#include "util/ArrayZeroizer.h"
#include "errors/EncryptionException.h"
#include "errors/IllegalArgumentException.h"

#include <time.h>

/* Intel Chipset CSP type */
#if !defined(PROV_INTEL_SEC)
# define PROV_INTEL_SEC        22
#endif // PROV_INTEL_SEC

/* Intel Chipset CSP name */
#if !defined(INTEL_DEF_PROV)
# define INTEL_DEF_PROV        L"Intel Hardware Cryptographic Service Provider"
#endif // INTEL_DEF_PROV

namespace esapi
{
  class AutoProvider
  {
  public:
    explicit AutoProvider(HCRYPTPROV& handle)
      : m_handle(handle) { }

    ~AutoProvider()
    {
      if(m_handle) {
        CryptReleaseContext(m_handle, 0);
        m_handle = NULL;
      }
    }
  private:
    AutoProvider& operator=(const AutoProvider&);

  private:
    HCRYPTPROV& m_handle;
  };

  bool RandomPool::GenerateKeyAndIv(byte* key, size_t ksize)
  {
    ASSERT(key && ksize);
    if(!key || !ksize) return false;

    size_t req = ksize;
    size_t idx = 0;

    // First try and pull bytes from Intel's hardware based RNG.
    // http://www.intel.com/design/software/drivers/platform/security.htm
    // http://www.intel.com/design/software/drivers/platform/archived_security.htm
    { 
      HCRYPTPROV hProvider = NULL;
      AutoProvider z1(hProvider);

      // Get a handle to the Intel CSP
      if(CryptAcquireContext(&hProvider, NULL, INTEL_DEF_PROV, PROV_INTEL_SEC, 0))
        {
          while(req)
            {
              CryptoPP::Timer timer;
              timer.StartTimer();

              BOOL result = CryptGenRandom(hProvider, 1, &key[idx]);
              ASSERT(result);
              if(!result) break; /* Failed */

              req--; idx++;

              // If it appears we have blocked, break and fall back to the base provider
              if(timer.ElapsedTime() > 1) break;
            }
        }
    }

    // Early out if possible.
    if(req == 0) return true;

    // Next, fall back to Windows CryptGenRandom
    { 
      HCRYPTPROV hProvider = NULL;
      AutoProvider z2(hProvider);

      // Get a handle to the default CSP
      if(!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
          // Get a handle to the base CSP
          if(!CryptAcquireContext(&hProvider, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0))
            {        
              // Create a new keyset as required (one of the joys of dealing with MS).
              // Once created, the previous calls to CryptAcquireContext will succeed.
              CryptAcquireContext(&hProvider, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
            }
        }
      // Get a random number
      if(hProvider && CryptGenRandom(hProvider, (DWORD)req, &key[idx]))
        {
          req = 0;
        }
    }

    return (req == 0);
  }

  bool RandomPool::GetTimeData(byte* data, size_t dsize)
  {
    ASSERT(data && dsize);
    if(!data || !dsize) return false;

    size_t idx = 0, rem = dsize, req = 0;

    LARGE_INTEGER li;
    if(::QueryPerformanceCounter(&li))
      {
        req = std::min(rem, sizeof(li));
        ::memcpy(data, &li, req);
        rem -= req; idx+= req;
      }

    // Any room remaining? There should be...
    if(!rem) return true;

    FILETIME ft;
    ::GetSystemTimeAsFileTime(&ft);
    req = std::min(rem, sizeof(ft));
    ::memcpy(data+idx, &ft, req);

    return true;
  }
}

