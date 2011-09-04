# OWASP Enterprise Security API (ESAPI)
# This file is part of the Open Web Application Security Project (OWASP)
# Enterprise Security API (ESAPI) project. For details, please see
# http://www.owasp.org/.
#
# The ESAPI is published by OWASP under the BSD license. You should read and
# accept the LICENSE before you use, modify, and/or redistribute this software.
#
# Copyright (c) 2011 - The OWASP Foundation

# Comeau C++ Compiler
# CXX =		como
# Intel ICC
# CXX =		icpc
# GNU C++ Compiler
CXX =		g++

DYNAMIC_LIB =	libesapi-c++.so
STATIC_LIB =	libesapi-c++.a

# Try and pick up on targets/goals.
# See https://lists.owasp.org/pipermail/owasp-esapi-c++/2011-August/000157.html for mixing and matching Debug/Release/Test from goals.

DEBUG_GOALS = $(filter $(MAKECMDGOALS), debug crypto codec codecs err errors ref reference)
ifneq ($(DEBUG_GOALS),)
  WANT_DEBUG := 1
endif

RELEASE_GOALS = $(filter $(MAKECMDGOALS), release all $(DYNAMIC_LIB) $(STATIC_LIB))
ifneq ($(RELEASE_GOALS),)
  WANT_RELEASE := 1
endif

TEST_GOALS = $(filter $(MAKECMDGOALS), test)
ifneq ($(TEST_GOALS),)
  WANT_TEST := 1
endif

# If nothing is specified, default to Test. This catch all is why
# CXXFLAGS are not set above in the MAKECMDGOALS tests.
ifeq ($(MAKECMDGOALS),)
  WANT_TEST := 1
endif

# libstdc++ debug: http://gcc.gnu.org/onlinedocs/libstdc++/manual/debug_mode.html
ifeq ($(WANT_DEBUG),1)
  CXXFLAGS += -D_GLIBCXX_DEBUG -DDEBUG=1 -g3 -ggdb -O0 -Dprivate=public -Dprotected=public
endif

ifeq ($(WANT_RELEASE),1)
  CXXFLAGS += -DNDEBUG=1 -g -O2
endif

ifeq ($(WANT_TEST),1)
  CXXFLAGS += -DESAPI_NO_ASSERT=1 -g2 -ggdb -O0 -Dprivate=public -Dprotected=public
endif

# For SafeInt. Painting with a broad brush, unsigned negation is bad becuase
# the bit pattern is negated, but the type remains the same. So a positive
# integer is never transformed into a negative integer as expected. It morphs
# into a bigger or smaller unsigned integer.
CXXFLAGS += -DSAFEINT_DISALLOW_UNSIGNED_NEGATION=1

EGREP = egrep

UNAME = uname

GCC_COMPILER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version")
INTEL_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\)")
COMEAU_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "comeau")

GCC40_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[0-9]|[5-9])")
GCC41_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[1-9]|[5-9])")
GCC43_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[3-9]|[5-9])")
GCC44_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[4-9]|[5-9])")
GCC45_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[5-9]|[5-9])")
GCC46_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[6-9]|[5-9])")

IS_LINUX = $(shell $(UNAME) 2>&1 | $(EGREP) -i -c "linux")

# Would like -fvisibility=hidden, but intel's syntax is:
# int foo(int a) __attribute__ ((visibility ("default")));
# MS and GCC allow the attribute at the beggingn of the declaraion.....
# See http://software.intel.com/sites/products/documentation/studio/composer/en-us/2011/compiler_c/optaps/common/optaps_cmp_visib.htm
ifneq ($(INTEL_COMPILER),0)
  CXXFLAGS += -pipe -std=c++0x -Wall -wd1011
endif

# GCC is usually a signed char, but not always (cf, ARM)
ifneq ($(GCC_COMPILER),0)
  CXXFLAGS += -pipe -fsigned-char -fmessage-length=0 -Woverloaded-virtual -Wreorder -Wformat=2 -Wformat-security
#  Too much Boost noise
#  CXXFLAGS += -Weffc++ -Wno-non-virtual-dtor
endif

# http://gcc.gnu.org/wiki/Visibility
# http://people.redhat.com/drepper/dsohowto.pdf
ifneq ($(GCC40_OR_LATER),0)
  CXXFLAGS += -fvisibility=hidden
endif

# http://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Optimize-Options.html
# http://www.linuxfromscratch.org/hints/downloads/files/ssp.txt
ifneq ($(GCC41_OR_LATER),0)
  ifeq ($(WANT_DEBUG),1)
    CXXFLAGS += -D_FORTIFY_SOURCE=2
    CXXFLAGS += -fstack-protector-all
  else
    CXXFLAGS += -fstack-protector
  endif  
endif

# -Wno-type-limit: for unsigned t<0 on template code, see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=23587
ifneq ($(GCC43_OR_LATER),0)
  CXXFLAGS += -Wall -Wextra -Wno-type-limits -Wno-unused
endif

# For unique_ptr - see http://gcc.gnu.org/onlinedocs/libstdc++/manual/api.html#api.rel_440
ifneq ($(GCC44_OR_LATER),0)
  CXXFLAGS += -std=c++0x
endif

# For nullptr - see http://gcc.gnu.org/projects/cxx0x.html
#ifneq ($(GCC46_OR_LATER),0)
#  CXXFLAGS += -std=c++0x // Included in 4.4
#endif

# http://lists.debian.org/debian-devel/2003/10/msg01538.html
ifneq ($(IS_LINUX), 0)
  CXXFLAGS += -D_REENTRANT
  LDLIBS += -lpthread
endif

ROOTSRCS =	src/EncoderConstants.cpp \
			src/ValidationErrorList.cpp

CODECSRCS =	src/codecs/Codec.cpp \
			src/codecs/PushbackString.cpp \
			src/codecs/HTMLEntityCodec.cpp \
			src/codecs/UnixCodec.cpp \
			src/codecs/WindowsCodec.cpp \
			src/codecs/LDAPCodec.cpp 

CRYPTOSRCS = src/crypto/PlainText.cpp \
			src/crypto/CipherText.cpp \
			src/crypto/SecretKey.cpp \
			src/crypto/SecureRandom.cpp \
			src/crypto/SecureRandomImpl.cpp \
			src/crypto/KeyGenerator.cpp \
			src/crypto/CryptoHelper.cpp \
			src/crypto/MessageDigest.cpp \
			src/crypto/MessageDigestImpl.cpp \
			src/crypto/RandomPool-Shared.cpp \
			src/crypto/RandomPool-Starnix.cpp \
			src/crypto/KeyDerivationFunction.cpp

ERRSRCS =   src/errors/EnterpriseSecurityException.cpp \
			src/errors/ValidationException.cpp

REFSRCS =   src/reference/DefaultEncoder.cpp \
			src/reference/DefaultEncryptor.cpp \
			src/reference/DefaultExecutor.cpp \
			src/reference/DefaultValidator.cpp \
			src/reference/IntegerAccessReferenceMap.cpp \
			src/reference/RandomAccessReferenceMap.cpp \
			src/reference/validation/BaseValidationRule.cpp \
			src/reference/validation/StringValidationRule.cpp

UTILSRCS =	src/util/SecureString.cpp \
			src/util/Mutex.cpp

LIBSRCS =	$(ROOTSRCS) \
			$(CODECSRCS) \
			$(CRYPTOSRCS) \
			$(ERRSRCS) \
			$(REFSRCS) \
			$(UTILSRCS)

TESTSRCS = 	test/TestMain.cpp \
			test/codecs/CodecTest.cpp \
			test/codecs/PushbackStringTest.cpp \
			test/codecs/HTMLEntityCodecTest.cpp \
			test/codecs/LDAPCodecTest.cpp \
			test/codecs/UnixCodecTest.cpp \
			test/crypto/PlainTextTest.cpp \
			test/crypto/CipherTextTest.cpp \
			test/crypto/SecretKeyTest.cpp \
			test/crypto/SecureRandomTest.cpp \
			test/crypto/KeyGeneratorTest.cpp \
			test/crypto/CryptoHelperTest.cpp \
			test/crypto/MessageDigestTest.cpp \
			test/crypto/KeyDerivationFunctionTest.cpp \
			test/errors/ValidationExceptionTest.cpp \
			test/reference/DefaultEncryptorTest.cpp \
			test/reference/DefaultEncoderTest.cpp \
#			test/reference/validation/StringValidationRuleTest.cpp \
			test/util/zAllocatorTest.cpp \
			test/util/SecureStringTest1.cpp \
			test/util/SecureStringTest2.cpp

ROOTOBJS =		$(ROOTSRCS:.cpp=.o)
CODECOBJS =		$(CODECSRCS:.cpp=.o)
CRYPTOOBJS =	$(CRYPTOSRCS:.cpp=.o)
ERROBJS =		$(ERRCSRCS:.cpp=.o)
REFOBJS =		$(REFCSRCS:.cpp=.o)
UTILOBJS =		$(UTILSRCS:.cpp=.o)

LIBOBJS =		$(LIBSRCS:.cpp=.o)

TESTOBJS =		$(TESTSRCS:.cpp=.o)

# OpenBSD needs the dash in ARFLAGS
AR =		ar
ARFLAGS = 	-rcs
RANLIB =	ranlib

CXXFLAGS +=	-I. -I./esapi -I./deps -I/usr/local/include

# -Wl,-z,relro: Make the GOT read-only after starting
# -Wl,-z,now: No lazy binding for PLT attacks
LDFLAGS +=	-L/usr/local/lib -L/usr/lib -Wl,--exclude-libs,ALL -Wl,-z,relro -Wl,-z,now
LDLIBS +=	-lcryptopp -lboost_regex-mt

TESTLIBS +=	-lboost_unit_test_framework-mt

# No extension, so no implicit rule. Hence we provide an empty rule for the dependency.
TESTTARGET = test/run_esapi_tests

# Might need this. TOOD: test and uncomment or remove
# ifeq ($(UNAME),Darwin)
#   AR = libtool
#   ARFLAGS = -static -o
#   CXX = c++
# endif

# Default rule for `make`
default: test

# Clear unneeded implicit rules
.SUFFIXES:
.SUFFIXES: .c .cpp .o

# If you are missing libcrypto++ or libcryptopp, see
# https://code.google.com/p/owasp-esapi-cplusplus/wiki/DevPrerequisites
$(DYNAMIC_LIB):	$(LIBOBJS)
	$(CXX) $(CXXFLAGS) -o lib/$@ $(LIBOBJS) $(LDFLAGS) -shared $(LDLIBS)

$(STATIC_LIB): $(LIBOBJS)
	$(AR) $(ARFLAGS) lib/$@ $(LIBOBJS)
	$(RANLIB) lib/$@

# `make all` builds the DSO and Archive. OPT=O2, SYM=G1, Asserts are off.
all: $(STATIC_LIB) $(DYNAMIC_LIB)

# `make` builds the DSO and runs the tests. OPT=O2, SYM=G1, ASSERTs are off.
# covered under the default rule above

# `make debug` builds the DSO and runs the tests. OPT=O0, SYM=G3, ASSERTs are on.
debug: test

# `make release` is `make all`. OPT=O2, SYM=G1, ASSERTs are off.
release: all test

# `make test` builds the DSO and runs the tests. OPT=O2, SYM=G3, ASSERTs are off.
test check: $(TESTOBJS) $(TESTTARGET) $(DYNAMIC_LIB)
	-$(CXX) $(CXXFLAGS) -fPIE -o $(TESTTARGET) $(TESTOBJS) -L./lib $(LDFLAGS) lib/$(DYNAMIC_LIB) $(LDLIBS) $(TESTLIBS)
	./$(TESTTARGET)

# Test compile codec sources, no final link
codec codecs: $(CODECOBJS)

# Test compile crypto sources, no final link
crypto: $(CRYPTOOBJS)

# Test compile error sources, no final link
err error: $(ERROBJS)

# Test compile reference sources, no final link
ref reference: $(REFOBJS)

# Test compile reference sources, no final link
util: $(UTILOBJS)

static: $(STATIC_LIB)

dynamic: $(DYNAMIC_LIB)

.cpp.o:
	$(CXX) $(CXXFLAGS) -fpic -c $< -o $@

# Empty target to satisy its use as a dependency in `make {test|check}`
$(TESTTARGET): ;

.PHONY: clean
clean:
	-rm -f $(LIBOBJS) lib/$(STATIC_LIB) lib/$(DYNAMIC_LIB) $(TESTOBJS) $(TESTTARGET) $(TESTTARGET).* *.dSYM *.core
