.POSIX:
include ../inc.mk

CS = c1 c2 c3 c4 c5 c6 c7 c8

all: $(CS)

c1: c1.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o c1 c1.o

c1.o: c1.cpp base64.h ../error.h
	$(CXX) $(CXXFLAGS) -c c1.cpp

c2:
	echo

c3:
	echo

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
