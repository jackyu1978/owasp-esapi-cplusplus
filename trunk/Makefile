CXX =		g++
CXXFLAGS = 	-O2 -g -Wall -fmessage-length=0

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

LIBS =		-lcryptopp -L/usr/local/lib -L/usr/lib -Llib

TARGET =	esapi-c++.so

TESTTARGET = test/run_esapi_tests

$(TARGET):	$(OBJS)
	$(CXX) $(CXXFLAGS) -shared -o $(TARGET) $(OBJS) $(LIBS)
	
.cpp.o:
	$(CXX) $(CXXFLAGS) -fpic -c $(INCLUDES) $< -o $@
	
$(OUT): $(OBJS)
	ar rcs $(OUT) $(OBJS)
	
test:	$(TESTOBJS)
	gcc -o $(TESTTARGET) $(TESTOBJS) $(LIBS)

runtests:	$(TESTOBJS) $(OBJS) 
	./$(TESTTARGET)

all:	$(TARGET) test runtests

clean:
	rm -f $(OBJS) $(TARGET) $(TESTOBJS) $(TESTTARGET).*
