.POSIX:
include ../inc.mk

CS = c02 c03 c04 c05

all: $(CS)

debug: CFLAGS += -DDEBUG
debug: $(CS)

hex.o: hex.c hex.h

base64.o: base64.c base64.h

c01: c01.o base64.o hex.o
	$(CC) $(CFLAGS) -o $@ $^

c01.o: c01.c base64.h hex.h ../error.h

$(CS):
	$(CC) $(CFLAGS) -o $@ $@.c

clean:
	rm -f $(CS) *.o

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<
