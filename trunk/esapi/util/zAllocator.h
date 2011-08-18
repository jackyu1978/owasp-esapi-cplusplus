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
 * @author David Anderson, david.anderson@aspectsecurity.com
 */

#pragma once

#include "EsapiCommon.h"

#include <memory>
#include <cstring>
#include <limits>

// For problems with allocator and its use, ask on comp.lang.c++
// For problems with the libstd-c++ implementation and use of allocator, ask on the
//   GCC mailing list (its easy to get off topic, use sparingly)
// For problems with _Alloc_hider, see http://gcc.gnu.org/ml/gcc-help/2011-08/msg00199.html.

namespace esapi
{
  template<typename T>
    class zallocator
    {
    public:

      typedef T value_type;
      typedef value_type* pointer;
      typedef const value_type* const_pointer;
      typedef value_type& reference;
      typedef const value_type& const_reference;
      typedef std::size_t size_type;
      typedef std::ptrdiff_t difference_type;

    public:

      // tame the optimizer
      static volatile void* g_dummy;

      template<typename U>
	    struct rebind {
	    typedef zallocator<U> other;
      };

      inline explicit zallocator() { }
      inline ~zallocator() { }
      inline zallocator(zallocator const&) { }

      template<typename U>
      inline explicit zallocator(zallocator<U> const&) { }

      // address
      inline pointer address(reference r) { return &r; }
      inline const_pointer address(const_reference r) { return &r; }

      // memory allocation
      inline pointer allocate(size_type cnt, typename std::allocator<void>::const_pointer = 0)
      {
        // Overflow/wrap is checked for by the container. Set a breakpoint
        // on max_size() and view the call stack (ie, the preceeding frame)
        // for verification.
        return reinterpret_cast<pointer>(::operator new(cnt * sizeof (T))); 
      }
    
      inline void deallocate(pointer p, size_type n)
      {
        // Pointer 'p' is checked for validity by the container. Because 'p'
        // is assigned to a static volatile pointer, the optimizer currently
        // does not optimize out the ::memset as dead code. Set a breakpoint
        // on line 66 and view the call stack (ie, the preceeding frame) for
        // verification. 
        ::memset(p, 0x00, n);
        g_dummy = p;
        ::operator delete(p);
      }

      // size
      inline size_type max_size() const
      {
        return std::numeric_limits<size_type>::max() / sizeof(T);
      }

      // construction/destruction
      inline void construct(pointer p, const T& t) { new(p) T(t); }
      inline void destroy(pointer p) { p->~T(); }

      inline bool operator==(zallocator const&) const { return true; }
      inline bool operator!=(zallocator const& a) const { return !operator==(a); }

      // http://code.google.com/p/owasp-esapi-cplusplus/issues/detail?id=11
#if defined(__GXX_EXPERIMENTAL_CXX0X__) && __GNUC__ == 4 && __GNUC_MINOR__ < 7
      template<typename U, typename... Args>
        void construct(U* p, Args&&... a)
      {
        ::new ((void*)p) U(std::forward<Args>(a)...);
      }

      template<typename U>
        void destroy(U* p)
        {
          delete p;
        }
#endif

    };

  // Storage and intialization
  template <class T>
    volatile void* zallocator<T>::g_dummy = NULL;

} // esapi
