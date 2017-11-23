.POSIX:
include ../inc.mk

CS = c1 c2 c3 c4 c5 c6 c7 c8

all: $(CS)

c1: c1.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o c1 c1.o

c1.o: c1.cpp base64.h hex.h ../error.h
	$(CXX) $(CXXFLAGS) -c c1.cpp

c2: c2.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o c2 c2.o

c2.o: c2.cpp hex.h ../error.h
	$(CXX) $(CXXFLAGS) -c c2.cpp

c3: c3.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o c3 c3.o

c3.o: c3.cpp hex.h ../error.h
	$(CXX) $(CXXFLAGS) -c c3.cpp

c4:
	echo

c5:
	echo

c6:
	echo

c7:
	echo

c8:
	echo

clean:
	rm -f $(CS) *.o
