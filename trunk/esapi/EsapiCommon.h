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

#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <cstring>

#include <assert.h>
#include <signal.h>

#include <iostream>

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
#elif defined(__unux__) || defined(__unux)
# define ESAPI_OS_UNIX 1
#endif

// Collect all the *nix's
#if defined(ESAPI_OS_LINUX) || defined(ESAPI_OS_UNIX) || defined(ESAPI_OS_APPLE)
# define ESAPI_OS_STARNIX 1
#endif

// Pick up the compiler
#if defined(_MSC) || defined(_MSC_VER)
# define ESAPI_CXX_MSVC 1
#elif defined(__ICC) || defined(__INTEL_COMPILER)
# define ESAPI_CXX_ICC 1
#elif defined(__COMO__) || defined(__COMO_VERSION__)
# define ESAPI_CXX_COMO 1
#elif defined(__GNUC__)
# define ESAPI_CXX_GCC 1
#endif

// And perhaps an environment
#if defined(CYGWIN) || defined(CYGWIN32)
# define ESAPI_ENV_CYGWIN 1
#elif defined(MINGW) || defined(MINGW32)
# define ESAPI_ENV_MINGW 1
#endif

// A debug assert which should be sprinkled liberally. This assert fires and then continues rather
// than calling abort(). Useful when examining negative test cases from the command line.
#if defined(ESAPI_BUILD_DEBUG) && defined(ESAPI_OS_STARNIX) && !defined(ESAPI_BUILD_TEST)
#  define ESAPI_ASSERT(exp) {                                           \
    if(!(exp)) {                                                        \
      std::cerr << "Assertion failed: " << (const char*)__FILE__ << "(" \
      << (int)__LINE__ << "): " << (const char*)__func__ << std::endl;  \
      raise(SIGTRAP);                                                   \
    }                                                                   \
  }
#elif defined(ESAPI_BUILD_DEBUG) && defined(ESAPI_OS_WINDOWS) && !defined(ESAPI_BUILD_TEST)
#  define ESAPI_ASSERT(exp) assert(exp)
#else
#  define ESAPI_ASSERT(exp) ((void)(exp))
#endif

// For the lazy folks like me!
#define ASSERT(x) ESAPI_ASSERT(x)

#if !defined(ESAPI_NO_SIGTRAP_HANDLER)
# if defined(ESAPI_OS_STARNIX) && defined(ESAPI_BUILD_DEBUG) && defined(__cplusplus)
// Add a TRAP handler for *nix, otherwise we still abort.
struct DebugTrapHandler
{
  DebugTrapHandler()
  {
    struct sigaction new_handler, old_handler;

    do
      {
        // Don't step on another's handler
        sigaction (SIGTRAP, NULL, &old_handler);
        if (old_handler.sa_handler != NULL) break;

        // Set up the structure to specify the null action.
        new_handler.sa_handler = &DebugTrapHandler::NullHandler;
        sigemptyset (&new_handler.sa_mask);
        new_handler.sa_flags = 0;

        // Install it
        sigaction (SIGTRAP, &new_handler, NULL);

      } while(0);
  }

  static void NullHandler(int unused) { }
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

// We *cannot* count on '!defined(nullptr)' since nullptr is a keyword.
// For Microsoft, nullptr is available in Visual Studio 2010 and
// above (version 1600), so we test for something earlier. For GCC, its
// 4.6 and above with -std=c++0x. Stroustrup gives us nullptr_t in the
// latest draft. C++0X, see http://www2.research.att.com/~bs/C++0xFAQ.html
// and http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2007/n2431.pdf
#if (defined(_MSC_VER) && (_MSC_VER < 1600)) || !defined(nullptr_t)
#  define nullptr NULL
#endif

#if defined(ESAPI_OS_STARNIX)
# include <pthread.h>
#endif

// Windows defines a min that clashes with std::min
#if defined(ESAPI_OS_WINDOWS)
# define NOMINMAX
#endif

// Supress MS warnings as required, but only if CL supports __pragma (VS 2008 and above)
#if defined(ESAPI_OS_WINDOWS) && (_MSC_VER >= 1500)
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

