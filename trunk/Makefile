# OWASP Enterprise Security API (ESAPI)
# This file is part of the Open Web Application Security Project (OWASP)
# Enterprise Security API (ESAPI) project. For details, please see
# <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
# Copyright 2011 - The OWASP Foundation

# Comeau
# CXX =		como
# Intel ICC
CXX =		icpc
# GNU Compiler Collection
# CXX =		g++

# Debug
# CXXFLAGS = -DDEBUG=1 -g3 -ggdb -O0
# Release
CXXFLAGS = -DNDEBUG=1 -g -O2

# For SafeInt. Painting with a broad brush, unsigned negation is bad becuase
# the bit pattern is negated, but the type remains the same. So an positive
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

SRCS =		src/reference/DefaultEncoder.cpp \
			src/errors/ValidationException.cpp \
			src/reference/DefaultValidator.cpp \
			src/EncoderConstants.cpp \
			src/reference/validation/BaseValidationRule.cpp \
			src/errors/EnterpriseSecurityException.cpp \
			src/ValidationErrorList.cpp \
			src/codecs/Codec.cpp \
			src/codecs/PushbackString.cpp \

TESTSRCS = test/codecs/CodecTest.cpp

OUT =		esapi-c++.a
OBJS =		$(SRCS:.cpp=.o)

TESTOBJS =	$(TESTSRCS:.cpp=.o)

INCLUDES =	-I. -I./esapi -I/usr/local/include -I/usr/include/c++/4.4 -I/boost_1_47_0 -I/Dev-Cpp/include

LIBS =		-lcryptopp -L/usr/local/lib -L/usr/lib -Llib -L/boost_1_47_0/stage/lib

TARGET =	esapi-c++.so

TESTTARGET = test/run_esapi_tests

$(TARGET):	$(OBJS)
	$(CXX) $(CXXFLAGS) -shared -o $(TARGET) $(OBJS) $(LIBS)
	
.cpp.o:
	$(CXX) $(CXXFLAGS) -fpic -c $(INCLUDES) $< -o $@
	
$(OUT): $(OBJS)
	ar rcs $(OUT) $(OBJS)
	
test:	$(TESTOBJS)
	$(CXX) -o $(TESTTARGET) $(TESTOBJS) $(LIBS) -lboost_system-mgw34-mt-1_47 -lboost_unit_test_framework-mgw34-mt-1_47

runtests:	$(TESTOBJS) $(OBJS) 
	./$(TESTTARGET)

all:	$(TARGET) test runtests

clean:
	rm -f $(OBJS) $(TARGET) $(TESTOBJS) $(TESTTARGET).*
