.POSIX:
include inc.mk

SETS = set01

all: sets

debug: CFLAGS += -DDEBUG
debug: sets

sets:
	-for s in $(SETS); do (cd $$s; $(MAKE)); done

clean:
	-for s in $(SETS); do (cd $$s; $(MAKE) clean); done
