/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2011 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeffrey Walton <a href="mailto:noloader@gmail.com">Jeffrey Walton, Vice President of Staples</a>
 * @author Kevin Wall <a href="mailto:kevin.w.wall@gmail.com">Kevin Wall, Vice President of Paperclips</a>
 * @created 2011
 */

#pragma once

// Only one or the other, but not both
#if (defined(DEBUG) || defined(_DEBUG)) && (defined(NDEBUG) || defined(_NDEBUG))
# error Both DEBUG and NDEBUG are defined.
#endif

// The only time we switch to debug is when asked. NDEBUG or {nothing} results in release build (fewer surprises at runtime).
#if defined(DEBUG) || defined(_DEBUG)
# define ESAPI_BUILD_DEBUG 1
#else
# define ESAPI_BUILD_RELEASE 1
#endif

// Pick up the architecture. See http://predef.sourceforge.net/prearch.html and http://msdn.microsoft.com/en-us/library/b0084kay%28v=vs.80%29.aspx.
#if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(_WIN64) || defined(_WIN64) || defined(_M_X64)
# define ESAPI_ARCH_X64 1
#elif defined(i386) || defined(__i386) || defined(__i386__)  || defined(_M_IX86)
# define ESAPI_ARCH_X86 1
#elif defined(__arm__) || defined(__arm) || defined(_M_ARM)
# define ESAPI_ARCH_ARM 1
#elif defined(__thumb__) || defined(__thumb) || defined(_M_THUMB)
# define ESAPI_ARCH_THUMB 1
#elif defined(__powerpc) || defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) || defined(_M_PPC)
# define ESAPI_ARCH_PPC 1
#endif

// Pick up the OS. Windows is fairly straight forward since WIN32 is almost always defined.
// For Linux and Uinx, the output of `cpp -dM < /dev/null | sort` is very helpful. Finally,
// see http://predef.sourceforge.net/prearch.html.
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)  || defined(UNDER_CE)
# define ESAPI_OS_WINDOWS 1
#elif defined(__APPLE__) || defined(__APPLE)
# define ESAPI_OS_APPLE 1
#elif defined(__linux__) || defined(__linux)
# define ESAPI_OS_LINUX 1
#elif defined(__sun) || defined(__SunOS)
# define ESAPI_OS_SUN 1
#elif defined(__FreeBSD__)
# define ESAPI_OS_FREEBSD 1
#elif defined(__OpenBSD__)
# define ESAPI_OS_OPENBSD 1
#elif defined(__unux__) || defined(__unux)
# define ESAPI_OS_UNIX 1
#endif

// Collect all the *nix's
#if defined(ESAPI_OS_LINUX) || defined(ESAPI_OS_UNIX) || defined(ESAPI_OS_APPLE) || defined(ESAPI_OS_SUN) || defined(ESAPI_OS_FREEBSD) || defined(ESAPI_OS_OPENBSD)
# define ESAPI_OS_STARNIX 1
#endif

// Pick up the compiler
#if defined(_MSC) || defined(_MSC_VER)
# define ESAPI_CXX_MSVC 1
#elif defined(__ICC) || defined(__INTEL_COMPILER)
# define ESAPI_CXX_ICC 1
#elif defined(__COMO__) || defined(__COMO_VERSION__)
# define ESAPI_CXX_COMO 1
#elif defined(__SUNPRO_C)
# define ESAPI_CXX_SUN 1
#elif defined(__GNUC__)
# define ESAPI_CXX_GCC 1
#endif

// And perhaps an environment
#if defined(CYGWIN) || defined(CYGWIN32)
# define ESAPI_ENV_CYGWIN 1
#elif defined(MINGW) || defined(MINGW32)
# define ESAPI_ENV_MINGW 1
#endif

// Race hunting with Helgrind and DRD.
// http://gcc.gnu.org/onlinedocs/libstdc++/manual/debug.html#debug.races.
#if defined(__GNUC__)
//#  define _GLIBCXX_SYNCHRONIZATION_HAPPENS_BEFORE(A) ANNOTATE_HAPPENS_BEFORE(A)
//#  define _GLIBCXX_SYNCHRONIZATION_HAPPENS_AFTER(A)  ANNOTATE_HAPPENS_AFTER(A)
#endif

#include <assert.h>
#include <signal.h>

#include <cstddef>
#include <iostream>
#include <sstream>
#include <memory>
#include <string>
#include <vector>
#include <list>
#include <map>

// Windows defines a min that clashes with std::min. We also need
// Windows 2000 (_WIN32_WINNT = 0x0500) for the WinCrypt gear
#if defined(ESAPI_OS_WINDOWS)
# define NOMINMAX
# define  _WIN32_WINNT 0x0500
# include <windows.h>
# include <Wincrypt.h>
# include <intrin.h>
#endif

#if defined(ESAPI_OS_STARNIX)
# include <pthread.h>
# include <errno.h>
#endif

// We *cannot* count on '!defined(nullptr)' since nullptr is a keyword.
// For Microsoft, nullptr is available in Visual Studio 2010 and
// above (version 1600), so we test for something earlier. For GCC, its
// 4.3 and above with -std=c++0x. Stroustrup gives us nullptr_t in the
// latest draft. C++0X, see http://www2.research.att.com/~bs/C++0xFAQ.html
// and http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2007/n2431.pdf
// For nullptr - see see http://gcc.gnu.org/projects/cxx0x.html.
#if (_MSC_VER >= 1600) || defined(nullptr_t)
# define ESAPI_CPLUSPLUS_NULLPTR 1
#endif

#if !defined(ESAPI_CPLUSPLUS_NULLPTR)
# define nullptr NULL
#endif

// A debug assert which should be sprinkled liberally. This assert fires and then continues rather
// than calling abort(). Useful when examining negative test cases from the command line.
#if (defined(ESAPI_BUILD_DEBUG) && defined(ESAPI_OS_STARNIX)) && !defined(ESAPI_NO_ASSERT)
#  define ESAPI_ASSERT1(exp) {                                    \
    if(!(exp)) {                                                  \
      std::ostringstream oss;                                     \
      oss << "Assertion failed: " << (char*)(__FILE__) << "(L"     \
          << (int)__LINE__ << "): " << (char*)(__func__)          \
          << std::endl;                                           \
      std::cerr << oss.str();                                     \
      raise(SIGTRAP);                                             \
    }                                                             \
  }
#  define ESAPI_ASSERT2(exp, msg) {                               \
    if(!(exp)) {                                                  \
      std::ostringstream oss;                                     \
      oss << "Assertion failed: " << (char*)(__FILE__) << "(L"     \
          << (int)__LINE__ << "): " << (char*)(__func__)          \
          << ": \"" << (msg) << "\"" << std::endl;                \
      std::cerr << oss.str();                                     \
      raise(SIGTRAP);                                             \
    }                                                             \
  }
#elif (defined(ESAPI_BUILD_DEBUG) && defined(ESAPI_OS_WINDOWS)) && !defined(ESAPI_NO_ASSERT)
#  define ESAPI_ASSERT1(exp) assert(exp)
#  define ESAPI_ASSERT2(exp, msg) assert(exp)
#else
#  define ESAPI_ASSERT1(exp) ((void)(exp))
#  define ESAPI_ASSERT2(exp, msg) ((void)(exp))
#endif

// For the lazy folks like me!
#define ASSERT(x) ESAPI_ASSERT1(x)

#if !defined(ESAPI_NO_ASSERT)
# if defined(ESAPI_OS_STARNIX) && defined(ESAPI_BUILD_DEBUG) && defined(__cplusplus)
// Add a TRAP handler for *nix, otherwise we still abort.
struct DebugTrapHandler
{
  DebugTrapHandler()
  {
    // http://pubs.opengroup.org/onlinepubs/007908799/xsh/sigaction.html
    struct sigaction new_handler, old_handler;

    do
      {
        int ret = 0;

        ret = sigaction (SIGTRAP, NULL, &old_handler);
        if (ret != 0) break; // Failed

        // Don't step on another's handler
        if (old_handler.sa_handler != NULL) break;

        // Set up the structure to specify the null action.
        new_handler.sa_handler = &DebugTrapHandler::NullHandler;
        new_handler.sa_flags = 0;

        ret = sigemptyset (&new_handler.sa_mask);
        if (ret != 0) break; // Failed

        // Install it
        ret = sigaction (SIGTRAP, &new_handler, NULL);
        if (ret != 0) break; // Failed

      } while(0);
  }

  static void NullHandler(int /*unused*/) { }
};

// We specify a relatively low priority, to make sure we run before other CTORs
// http://gcc.gnu.org/onlinedocs/gcc/C_002b_002b-Attributes.html#C_002b_002b-Attributes
static const DebugTrapHandler g_dummyHandler __attribute__ ((init_priority (110)));
# endif // *nix debug
#endif // ESAPI_NO_SIGTRAP_HANDLER

// For counting elements
#if !defined(COUNTOF)
# if defined(_countof)
#  define COUNTOF(x) _countof(x)
# else
#  define COUNTOF(x) (sizeof(x)/sizeof((x)[0]))
# endif
#endif

// So common, don't put in a namespace
#if !defined(byte)
typedef unsigned char byte;
#endif

// Supress MS warnings as required, but only if CL supports __pragma (VS 2008 and above)
#if defined(ESAPI_CXX_MSVC) && (_MSC_VER >= 1500)
# define ESAPI_MS_NO_WARNING(x)                 \
  __pragma(warning(disable:x))
# define ESAPI_MS_DEF_WARNING(x)                \
  __pragma(warning(default:x))
# define ESAPI_MS_WARNING_PUSH(x)               \
  __pragma(warning(push, x))
# define ESAPI_MS_WARNING_POP()                 \
  __pragma(warning(pop))
#else
# define ESAPI_MS_NO_WARNING(x)
# define ESAPI_MS_DEF_WARNING(x)
# define ESAPI_MS_WARNING_PUSH(x)
# define ESAPI_MS_WARNING_POP() 
#endif

// Kill MS warning on non-standard template extension from Crypto++
ESAPI_MS_NO_WARNING(4231)
// STL gear needs to have dll-interface to be used by clients
//   http://msdn.microsoft.com/en-us/library/3tdb471s(v=VS.90).aspx
//   http://msdn.microsoft.com/en-us/library/esew7y1w(v=VS.90).aspx
ESAPI_MS_NO_WARNING(4251)
ESAPI_MS_NO_WARNING(4275)
// Knock out the MS Warning about CXX ignoring exception lists
ESAPI_MS_NO_WARNING(4290)
// Remove warnings about unused functions
ESAPI_MS_NO_WARNING(4505)

#if defined(ESAPI_CXX_MSVC)
# if defined ESAPI_MS_DLL_EXPORTS
#  define ESAPI_EXPORT __declspec(dllexport)
#  define ESAPI_PRIVATE
# elif defined ESAPI_MS_DLL_IMPORTS
#  define ESAPI_EXPORT __declspec(dllimport)
#  define ESAPI_PRIVATE
# else
#  define ESAPI_EXPORT
#  define ESAPI_PRIVATE
# endif
#elif defined(ESAPI_CXX_ICC)
# define ESAPI_EXPORT
# define ESAPI_PRIVATE
#elif defined(ESAPI_CXX_GCC)
# if (__GNUC__ >= 4)
#  define ESAPI_EXPORT __attribute__ ((visibility (L"default")))
#  define ESAPI_PRIVATE  __attribute__ ((visibility (L"hidden")))
# else
#  define ESAPI_EXPORT
#  define ESAPI_PRIVATE
# endif
#endif

#if defined(ESAPI_CXX_MSVC)
# pragma intrinsic(_ReadWriteBarrier)
# define MEMORY_BARRIER() _ReadWriteBarrier()
#elif defined(ESAPI_CXX_ICC)
# define MEMORY_BARRIER() __memory_barrier()
#elif defined(ESAPI_CXX_GCC)
# define MEMORY_BARRIER() __asm__ __volatile__ (L"" ::: "memory")
#else
# error "Unknown compiler"
#endif

// Some stuff needs to be exported for testing. For example,
// RandomPool is meant to be used only by secure random.
#if !defined(ESAPI_BUILD_RELEASE) && !defined(ESAPI_MS_DLL_EXPORTS)
# define ESAPI_TEST_EXPORT ESAPI_EXPORT
#else
# define ESAPI_TEST_EXPORT
#endif

// Defines the Char, String and typees such as Array
#include "EsapiTypes.h"
