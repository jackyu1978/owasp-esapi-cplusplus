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
# CXX = como
# Intel ICC
# CXX = icpc
# GNU C++ Compiler
# CXX =	g++

# Default rule for `make`
default: test

# Clear unneeded implicit rules
.SUFFIXES:
.SUFFIXES: .c .cpp .cxx .o .h .hpp

# Note: we use both $CPPFLAGS and $CXXFLAGS for recipes which include $CXX.
# See http://www.gnu.org/s/hello/manual/make/Catalogue-of-Rules.html.

DYNAMIC_LIB =	libesapi-c++.so
STATIC_LIB =	libesapi-c++.a

# Try and pick up on targets/goals.
# See https://lists.owasp.org/pipermail/owasp-esapi-c++/2011-August/000157.html for mixing and matching Debug/Release/Test from goals.

DEBUG_GOALS = $(filter $(MAKECMDGOALS), debug)
ifneq ($(DEBUG_GOALS),)
  WANT_DEBUG := 1
endif

TEST_GOALS = $(filter $(MAKECMDGOALS), test)
ifneq ($(TEST_GOALS),)
  WANT_DEBUG := 0
  WANT_TEST := 1
endif

RELEASE_GOALS = $(filter $(MAKECMDGOALS), release all $(DYNAMIC_LIB) $(STATIC_LIB) crypto codec codecs err errors ref reference)
ifneq ($(RELEASE_GOALS),)
  WANT_DEBUG := 0
  WANT_TEST := 0
  WANT_RELEASE := 1
endif

# If nothing is specified, default to Test.
ifeq ($(WANT_DEBUG),0)
  ifeq ($(WANT_RELEASE),0)
    WANT_TEST := 1
  endif
endif

# libstdc++ debug: http://gcc.gnu.org/onlinedocs/libstdc++/manual/debug_mode.html
ifeq ($(WANT_DEBUG),1)
  override CXXFLAGS += -D_GLIBCXX_DEBUG -DDEBUG=1 -g3 -ggdb -O0 -Dprivate=public -Dprotected=public
endif

ifeq ($(WANT_RELEASE),1)
  override CXXFLAGS += -DNDEBUG=1 -g -O2
endif

ifeq ($(WANT_TEST),1)
  override CXXFLAGS += -DESAPI_NO_ASSERT=1 -g2 -ggdb -O0 -Dprivate=public -Dprotected=public
endif

# For SafeInt. Painting with a broad brush, unsigned negation is bad becuase
# the bit pattern is negated, but the type remains the same. So a positive
# integer is never transformed into a negative integer as expected. It morphs
# into a bigger or smaller unsigned integer.
override CXXFLAGS += -DSAFEINT_DISALLOW_UNSIGNED_NEGATION=1

EGREP = egrep
UNAME = uname

IS_X86_OR_X64 = $(shell uname -m | $(EGREP) -i -c "i.86|x86|i86|i386|i686|amd64|x86_64")
IS_OPENBSD = $(shell uname -a | $(EGREP) -i -c "openbsd")

GCC_COMPILER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version')
INTEL_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c '\(icc\)')
COMEAU_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c 'comeau')
SUN_COMPILER = $(shell $(CXX) -V 2>&1 | $(EGREP) -i -c 'cc: sun')

GCC40_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[0-9]|[5-9])')
GCC41_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[1-9]|[5-9])')
GCC42_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[2-9]|[5-9])')
GCC43_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[3-9]|[5-9])')
GCC44_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[4-9]|[5-9])')
GCC45_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[5-9]|[5-9])')
GCC46_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[6-9]|[5-9])')
GCC47_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -i -c '^gcc version (4\.[7-9]|[5-9])')

# -z nodlopen: Do not allow an attacker to dlopen us
# --exclude-libs: keep other library symbols (which we depend upon) from being exported (by us)
# -z relro: Make the GOT read-only after starting to mitigate overwrite attacks
# -z now: No lazy binding to mitigate PLT attacks

# For -nodlopen, which appeared around 2000 (Binutils 2.10).
# http://sourceware.org/ml/binutils/2011-09/msg00049.html
GNU_LD210_OR_LATER = $(shell $(LD) -v 2>&1 | $(EGREP) -i -c '^gnu ld .* (2\.1[0-9]|2\.[2-9])')
# For -relro and -now, which appeared around 6/2004 (Binutils 2.15) (see the ld/ChangeLog-2004 in BinUtils).
GNU_LD215_OR_LATER = $(shell $(LD) -v 2>&1 | $(EGREP) -i -c '^gnu ld .* (2\.1[5-9]|2\.[2-9])')
# For --exclude-libs, which appeared around 4/2002, but was ELF'd in 10/2005 
# http://sourceware.org/ml/binutils/2011-09/msg00064.html
GNU_LD216_OR_LATER = $(shell $(LD) -v 2>&1 | $(EGREP) -i -c '^gnu ld .* (2\.1[6-9]|2\.[2-9])')

IS_LINUX = $(shell $(UNAME) 2>&1 | $(EGREP) -i -c 'linux')
IS_SOLARIS = $(shell $(UNAME) -a 2>&1 | $(EGREP) -i -c 'solaris')
IS_BSD = $(shell $(UNAME) 2>&1 | $(EGREP) -i -c '(openbsd|freebsd|netbsd)')

# Fall back to g++ if CXX is not specified
ifeq ($strip $(CXX)),)
  CXX = g++
endif

# Try and pick up SunStudio on Solaris. For whatever reason OpenSolaris is using CXX=g++
# (from the environment?), which is blowing up on OpenSolaris with a 'g++: command not found'.
# Failure is a mystery, as it appears gcc/g++ installed correctly. So we force 'CC' from
# Sun Studio, see http://opensolaris.org/jive/thread.jspa?messageID=523996.
# If Solaris is not picked up automatically, invoke make with CC: `make test CXX=CC`
ifeq ($(IS_SOLARIS),1)
  CXX = CC
endif

# Would like -fvisibility=hidden for ICC, but Intel's syntax hinders hidden by default:
# int foo(int a) __attribute__ ((visibility ("default")));
# MS and GCC allow the attribute at the beginning of the declaraion, ICC does not...
# http://software.intel.com/sites/products/documentation/studio/composer/en-us/2011/compiler_c/optaps/common/optaps_cmp_visib.htm
ifeq ($(INTEL_COMPILER),1)
  override CXXFLAGS += -pipe -std=c++0x -Wall -wd1011
endif

# GCC is usually a signed char, but not always (cf, ARM). We'd also like to cut the UTF-16 problem
# off at the pass, but it looks like we need to re-complile a bunch of stuff when using -fshort-wchar.
# http://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html#Optimize-Options
ifeq ($(GCC_COMPILER),1)
  override CXXFLAGS += -pipe -fsigned-char -fmessage-length=0 -Woverloaded-virtual -Wreorder
  override CXXFLAGS += -Wformat=2 -Wformat-security
  override CXXFLAGS += -Wno-unused
#  Too much Boost noise
#  override CXXFLAGS += -Weffc++ -Wno-non-virtual-dtor
endif

# http://gcc.gnu.org/wiki/Visibility
# http://people.redhat.com/drepper/dsohowto.pdf
ifeq ($(GCC40_OR_LATER),1)
  override CXXFLAGS += -fvisibility=hidden
endif

# http://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Optimize-Options.html
# http://www.linuxfromscratch.org/hints/downloads/files/ssp.txt
ifeq ($(GCC41_OR_LATER),1)
  ifeq ($(WANT_DEBUG),1)
    override CXXFLAGS += -D_FORTIFY_SOURCE=2
    override CXXFLAGS += -fstack-protector-all
  else
    override CXXFLAGS += -fstack-protector
  endif  
endif

# -Wno-type-limit: for unsigned t<0 on template code, http://gcc.gnu.org/bugzilla/show_bug.cgi?id=23587
# "C++0X features first appear", http://gcc.gnu.org/onlinedocs/libstdc++/manual/api.html#api.rel_430
ifeq ($(GCC43_OR_LATER),1)
  override CXXFLAGS += -Wall -Wextra -Wno-unused -Wno-type-limits
  override CXXFLAGS += -std=c++0x
endif

# http://gcc.gnu.org/wiki/Atomic/GCCMM/ExecutiveSummary
# http://gcc.gnu.org/wiki/Atomic/GCCMM/DataRaces
ifeq ($(GCC47_OR_LATER),1)
  override CXXFLAGS += -fmemory-model=c++0x
endif

# http://lists.debian.org/debian-devel/2003/10/msg01538.html
ifeq ($(IS_LINUX),1)
  override CXXFLAGS += -D_REENTRANT
  LDLIBS += -lpthread
endif

# Add paths
override CXXFLAGS +=	-I. -I./esapi -I./deps -I/usr/local/include -I/usr/include

ROOTSRCS =	src/EncoderConstants.cpp \
			src/ValidationErrorList.cpp \
			src/DummyConfiguration.cpp

CODECSRCS =	src/codecs/Codec.cpp \
			src/codecs/PushbackString.cpp \
			src/codecs/HTMLEntityCodec.cpp \
			src/codecs/UnixCodec.cpp \
			src/codecs/WindowsCodec.cpp \
			src/codecs/LDAPCodec.cpp 

CRYPTOSRCS = src/crypto/PlainText.cpp \
			src/crypto/CipherSpec.cpp \
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

UTILSRCS =	src/util/Mutex.cpp \
			src/util/SecureArray.cpp \
			src/util/SecureString.cpp \
			src/util/TextConvert-Starnix.cpp

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
			test/crypto/CipherSpecTest.cpp \
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
			test/util/zAllocatorTest.cpp \
			test/util/SecureByteArrayTest.cpp \
			test/util/SecureIntArrayTest.cpp \
			test/util/SecureStringTest1.cpp \
			test/util/SecureStringTest2.cpp \
			test/util/TextConvertTest.cpp \
			test/reference/validation/StringValidationRuleTest.cpp

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

override LDFLAGS +=	-L/usr/local/lib -L/usr/lib

# Linker hardening
ifeq ($(GNU_LD210_OR_LATER),1)
  override LDFLAGS +=	-Wl,-z,nodlopen -Wl,-z,nodldump
endif

# Linker hardening
ifeq ($(GNU_LD215_OR_LATER),1)
  override LDFLAGS +=	-Wl,-z,relro -Wl,-z,now
endif

# Add -PIE to x86 executables (missing on HPPA, ARM, and others)
ifeq ($(GNU_LD216_OR_LATER),1)
  ifneq ($(IS_X86_OR_X64),0)
    EXE_ASLR = -fpie
  endif
endif

# Reduce the size of the export table
ifeq ($(GNU_LD216_OR_LATER),1)
  override LDFLAGS +=	-Wl,--exclude-libs,ALL
endif

LDLIBS 		+= -lcryptopp -lboost_regex
TESTLDFLAGS	+= -L/usr/local/lib -L/usr/lib
TESTLDLIBS 	+= $(LDLIBS) -lboost_unit_test_framework

# No extension, so no implicit rule. Hence we provide an empty rule for the dependency.
TESTTARGET = test/run_esapi_tests

# Might need this. TOOD: test and uncomment or remove
# ifeq ($(UNAME),Darwin)
#   AR = libtool
#   ARFLAGS = -static -o
#   CXX = c++
# endif

# If you are missing libcrypto++ or libcryptopp, see
# https://code.google.com/p/owasp-esapi-cplusplus/wiki/DevPrerequisites
$(DYNAMIC_LIB):	$(LIBOBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o lib/$@ $(LIBOBJS) $(LDFLAGS) -shared $(LDLIBS)

$(STATIC_LIB): $(LIBOBJS)
	$(AR) $(ARFLAGS) lib/$@ $(LIBOBJS)
	$(RANLIB) lib/$@

# `make all` builds the DSO and Archive. OPT=O2, SYM=G1, Asserts are off.
all: $(STATIC_LIB) $(DYNAMIC_LIB)
static: $(STATIC_LIB)
dynamic: $(DYNAMIC_LIB)

# `make debug` builds the DSO and runs the tests. OPT=O0, SYM=G3, ASSERTs are on.
debug: $(DYNAMIC_LIB) test

# `make release` is `make all`. OPT=O2, SYM=G1, ASSERTs are off.
release: $(DYNAMIC_LIB) test

# `make test` builds the DSO and runs the tests. OPT=O2, SYM=G3, ASSERTs are off.
test check: $(DYNAMIC_LIB) $(TESTOBJS) $(TESTTARGET)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(EXE_ASLR) -o $(TESTTARGET) $(TESTOBJS) $(TESTLDFLAGS) $(TESTLDLIBS) lib/$(DYNAMIC_LIB)
	./$(TESTTARGET)

# Test compile codec sources, no final link
codec codecs: $(CODECOBJS)

# Test compile crypto sources, no final link
crypto: $(CRYPTOOBJS)

# Test compile error sources, no final link
err error: $(ERROBJS)

# Test compile reference sources, no final link
ref reference: $(REFOBJS)

# Test compile utility sources, no final link
util: $(UTILOBJS)

.cpp.o:
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fpic -c $< -o $@

# Empty target to satisy its use as a dependency in `make {test|check}`
$(TESTTARGET): ;

.PHONY: clean
clean:
	-rm -f $(LIBOBJS) lib/$(STATIC_LIB) lib/$(DYNAMIC_LIB) $(TESTOBJS) $(TESTTARGET) $(TESTTARGET).* *.dSYM core *.core
