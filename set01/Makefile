.POSIX:
include ../inc.mk

CS = c02 c03 c04 c05

all: $(CS)

c01: c01.o
	$(CC) $(CFLAGS) -o c01 c01.o

c01.o: c01.c base64.h ../error.h
	$(CC) $(CFLAGS) -c c01.c

$(CS):
	$(CC) $(CFLAGS) -o $@ $@.c

clean:
	rm -f $(CS)
