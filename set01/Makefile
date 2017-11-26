.POSIX:
include ../inc.mk

CS = c01 c02 c03 c04 c05

all: $(CS)

debug: CFLAGS += -DDEBUG
debug: $(CS)

base64.o: base64.c base64.h

hex.o: hex.c hex.h

score.o: score.c score.h

c01: c01.o base64.o hex.o
	$(CC) $(CFLAGS) -o $@ $^

c01.o: c01.c base64.h hex.h ../error.h

c02: c02.o hex.o
	$(CC) $(CFLAGS) -o $@ $^

c02.o: c02.c hex.h ../error.h

c03: c03.o hex.o score.o
	$(CC) $(CFLAGS) -o $@ $^

c03.o: c03.c hex.h score.h ../error.h

c04: c04.o score.o
	$(CC) $(CFLAGS) -o $@ $^

c04.o: c04.c score.h ../error.h

c05: c05.o
	$(CC) $(CFLAGS) -o $@ $^

c05.o: c05.c ../error.h

clean:
	rm -f $(CS) *.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
