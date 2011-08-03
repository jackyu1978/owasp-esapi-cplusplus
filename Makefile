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

# Debug
# CXXFLAGS = -DDEBUG=1 -g3 -ggdb -O0
# Release
CXXFLAGS = 	-DNDEBUG=1 -g -O2

# For SafeInt. Painting with a broad brush, unsigned negation is bad becuase
# the bit pattern is negated, but the type remains the same. So a positive
# integer is never transformed into a negative integer as expected. It morphs
# into a bigger or smaller unsigned integer.
CXXFLAGS += -DSAFEINT_DISALLOW_UNSIGNED_NEGATION=1

EGREP = egrep

GCC_COMPILER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version")
INTEL_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\)")
COMEAU_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "comeau")

GCC43_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[3-9]|[5-9])")
GCC46_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[6-9]|[5-9])")

ifneq ($(INTEL_COMPILER),0)
  CXXFLAGS += -pipe -std=c++0x -Wall -wd1011
endif

# GCC is usually a signed char, but not always (cf, ARM)
ifneq ($(GCC_COMPILER),0)
  CXXFLAGS += -pipe -fsigned-char -fmessage-length=0
endif

# -Wno-type-limit: for unsigned t<0 on template code, see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=23587
ifneq ($(GCC43_OR_LATER),0)
  CXXFLAGS += -Wall -Wextra -Wno-type-limits -Wno-unused
endif

# For nullptr - see http://gcc.gnu.org/projects/cxx0x.html
ifneq ($(GCC46_OR_LATER),0)
  CXXFLAGS += -std=c++0x
endif

LIBSRCS =	src/reference/DefaultEncoder.cpp \
			src/errors/ValidationException.cpp \
			src/reference/DefaultValidator.cpp \
			src/EncoderConstants.cpp \
			src/reference/validation/BaseValidationRule.cpp \
			src/errors/EnterpriseSecurityException.cpp \
			src/ValidationErrorList.cpp \
			src/codecs/Codec.cpp \
			src/codecs/PushbackString.cpp \

TESTSRCS = 	test/codecs/CodecTest.cpp \
			test/codecs/PushbackStringTest.cpp

LIBOBJS =	$(LIBSRCS:.cpp=.o)
TESTOBJS =	$(TESTSRCS:.cpp=.o)

# OpenBSD needs the dash in ARFLAGS
AR =		ar
ARFLAGS = 	-rcs
RANLIB =	ranlib

DYNAMIC_LIB =	lib/libesapi-c++.so
STATIC_LIB =	lib/libesapi-c++.a

INCLUDES =	-I. -I./esapi -I/usr/local/include

LDFLAGS =	-L/usr/local/lib -L/usr/lib -Llib
LDLIBS =	-lcryptopp

TESTTARGET = test/run_esapi_tests

# http://lists.debian.org/debian-devel/2003/10/msg01538.html
ifeq ($(UNAME),Linux)
  LDFLAGS += -D_REENTRANT
  LDLIBS += -lpthreads
endif

# Might need this. TOOD: test and uncomment or remove
# ifeq ($(UNAME),Darwin)
#   AR = libtool
#   ARFLAGS = -static -o
#   CXX = c++
# endif

$(DYNAMIC_LIB):	$(LIBOBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(LIBOBJS) $(LDFLAGS) -shared $(LDLIBS)
	
$(STATIC_LIB): $(LIBOBJS)
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@

.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -fpic -c $< -o $@

check test: $(TESTOBJS) $(DYNAMIC_LIB) $(TESTTARGET)
	-$(CXX) $(CXXFLAGS) -o $(TESTTARGET) $(TESTOBJS) $(LDFLAGS) $(LDLIBS) -lboost_filesystem -lboost_unit_test_framework
	./$(TESTTARGET)

$(TESTTARGET): ;

all: $(STATIC_LIB) $(DYNAMIC_LIB) test

clean:
	-rm -f $(LIBOBJS) $(STATIC_LIB) $(DYNAMIC_LIB) $(TESTOBJS) $(TESTTARGET).* *.dSYM *.core
