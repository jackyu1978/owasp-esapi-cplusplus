# -----------------------------------------------------------------------------------------------------------
# This software is licensed under the Microsoft Public License (Ms-PL).
# For more information about Microsoft open source licenses, refer to 
# http://www.microsoft.com/opensource/licenses.mspx
# 
# This license governs use of the accompanying software. If you use the software, you accept this license. 
# If you do not accept the license, do not use the software.
# 
# Definitions
# The terms "reproduce," "reproduction," "derivative works," and "distribution" have the same meaning here 
# as under U.S. copyright law. A "contribution" is the original software, or any additions or changes to 
# the software. A "contributor" is any person that distributes its contribution under this license. 
# "Licensed patents" are a contributor's patent claims that read directly on its contribution.
# 
# Grant of Rights
# (A) Copyright Grant- Subject to the terms of this license, including the license conditions and limitations 
# in section 3, each contributor grants you a non-exclusive, worldwide, royalty-free copyright license to 
# reproduce its contribution, prepare derivative works of its contribution, and distribute its contribution 
# or any derivative works that you create.
# 
# (B) Patent Grant- Subject to the terms of this license, including the license conditions and limitations in 
# section 3, each contributor grants you a non-exclusive, worldwide, royalty-free license under its licensed 
# patents to make, have made, use, sell, offer for sale, import, and/or otherwise dispose of its contribution 
# in the software or derivative works of the contribution in the software.
# 
# Conditions and Limitations
# (A) No Trademark License- This license does not grant you rights to use any contributors' name, logo, 
#     or trademarks. 
# (B) If you bring a patent claim against any contributor over patents that you claim are infringed by the 
#     software, your patent license from such contributor to the software ends automatically. 
# (C) If you distribute any portion of the software, you must retain all copyright, patent, trademark, and 
#     attribution notices that are present in the software. 
# (D) If you distribute any portion of the software in source code form, you may do so only under this license 
#     by including a complete copy of this license with your distribution. If you distribute any portion of the 
#     software in compiled or object code form, you may only do so under a license that complies with this license. 
# (E) The software is licensed "as-is." You bear the risk of using it. The contributors give no express warranties, 
#     guarantees, or conditions. You may have additional consumer rights under your local laws which this license 
#     cannot change. To the extent permitted under your local laws, the contributors exclude the implied warranties 
#     of merchantability, fitness for a particular purpose and non-infringement.
# 
# Copyright (c) OWASP Project (https://www.owasp.org), 2011. All rights reserved.
# -----------------------------------------------------------------------------------------------------------


# NDEBUG: standard POSIX define for 'release' builds
# -g: debugging information, see http://gcc.gnu.org/ml/gcc-help/2005-03/msg00032.html
# -O2: optimization level, see http://gcc.gnu.org/onlinedocs/gcc-4.2.4/gcc/Optimize-Options.html
# -pipe: use pipes instead of temp files, see http://gcc.gnu.org/onlinedocs/gcc-4.2.4/gcc/Overall-Options.html
# -fwrapv: wrap (carry) and overflow is expected, see http://www.airs.com/blog/archives/120

# Pick a compiler
# CXX = como
# CXX = icpc
CXX = g++

# Pick Debug or Release
# CXXFLAGS = -DDEBUG=1 -g3 -ggdb -O0
CXXFLAGS += -DNDEBUG=1 -g -O2

# Painting with a broad brush, unsigned negation is bad becuase the bit pattern is negated,
# but the type remains the same. So an positive integer is never transformed into a negative
# integer as expected. It morphs into a bigger or smaller unsigned integer.
CXXFLAGS += -DSAFEINT_DISALLOW_UNSIGNED_NEGATION=1

EGREP = egrep
INCLUDES += -I./. -I../.

GCC_COMPILER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version")
INTEL_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -c "\(ICC\)")
COMEAU_COMPILER = $(shell $(CXX) --version 2>&1 | $(EGREP) -i -c "comeau")

GCC43_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[3-9]|[5-9])")
GCC44_OR_LATER = $(shell $(CXX) -v 2>&1 | $(EGREP) -c "^gcc version (4.[4-9]|[5-9])")

ifneq ($(INTEL_COMPILER),0)
  CXXFLAGS += -pipe -std=c++0x -Wall -wd1011
endif

ifneq ($(GCC_COMPILER),0)
  CXXFLAGS += -pipe -Woverloaded-virtual
endif

# -Wno-type-limit: for unsigned t<0 on template code, see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=23587
ifneq ($(GCC43_OR_LATER),0)
  CXXFLAGS += -Wall -Wextra -Wno-type-limits -Wno-unused
endif

# For nullptr and unique_ptr - see http://gcc.gnu.org/projects/cxx0x.html
ifneq ($(GCC44_OR_LATER),0)
# Commented out until the tables are fixed. See comment that follows.
#  CXXFLAGS += -std=c++0x
endif

# GCC 4.4.3 on Ubuntu is nt adding the includes????
CXXFLAGS += $(INCLUDES)

#According to Jonathan Wakely over at GCC list, -std=c++0x and
#-fpermissive are an odd combination. See "Question on GCC 4.6 and
#-fpermissive", http://gcc.gnu.org/ml/gcc-help/2011-08/msg00136.html.
#
#There is a switch to suppress the narrowing warnings, but apparently
#its available in GCC 4.7. I tested on GCC 4.6, and -Wno-narrow and
#-Wno-narrowing did not suppress.
#
#At this point, I think the best course of action is to remove
#-std=c++0x. Its just too distracting and any useful warnings are
#lost in the noise. As soon as (1) the tables are fixed or (2)
#narrowing warnings can be suppressed, we should add -std=c++0x.

RUNTIME_SRCS = IncDecVerify.cpp AddVerify.cpp SubVerify.cpp MultVerify.cpp DivVerify.cpp ModVerify.cpp NegVerify.cpp PtrVerify.cpp
RUNTIME_OBJS = $(RUNTIME_SRCS:.cpp=.o)

all: TestMain.exe
	-./TestMain.exe

test check: TestMain.exe
	-./TestMain.exe

# TestMain.cpp is a run time test
TestMain.exe: SafeInt3.hpp TestMain.cpp $(RUNTIME_OBJS)
	$(CXX) $(CXXFLAGS) TestMain.cpp $(RUNTIME_OBJS) -o $@

SafeInt3.hpp: ;

.PHONY: clean	
clean:
	-rm -rf *.exe *.dSYM *.o *.core
