.POSIX:
include ../inc.mk

EXECS = c1 c2 c3 c4

all: $(EXECS)

$(EXECS):
	$(CC) $(CFLAGS) -o $@ $@.c

clean:
	rm -f $(EXECS)
