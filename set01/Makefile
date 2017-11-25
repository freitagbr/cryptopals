.POSIX:
include ../inc.mk

CS = c01 c02 c03 c04 c05

all: $(CS)

$(CS):
	$(CC) $(CFLAGS) -o $@ $@.c

clean:
	rm -f $(CS)
