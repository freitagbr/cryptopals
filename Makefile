# Copyright (c) 2018 Brandon Freitag <freitagbr@gmail.com>

NAME     := cryptopals
SRCDIR   := cryptopals
BUILDDIR := build
BINDIR   := $(BUILDDIR)/bin
LIBDIR   := $(BUILDDIR)/lib
OBJDIR   := $(BUILDDIR)/obj
INCLUDES := -I./

CSTD     := -std=c89
WARNINGS := -Wall -Wextra -Werror -pedantic
OPTIMIZE := -O

CFLAGS   := $(CSTD) $(WARNINGS) $(OPTIMIZE) $(INCLUDES)
LDLIBS   := -lm -lssl -lcrypto
VALGRIND := valgrind

LIBSRCS  := $(wildcard $(SRCDIR)/*.c)
LIBOBJS  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(LIBSRCS))
LIB      := $(LIBDIR)/lib$(NAME).a

BINSRCS  := $(wildcard $(SRCDIR)/set*/*.c)
BINOBJS  := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(BINSRCS))
BINS     := $(patsubst $(OBJDIR)/%.o,$(BINDIR)/%,$(BINOBJS))


# top-level targets

.PHONY: all debug test valgrind sets clean

all: sets

debug: clean
debug: CFLAGS += -DDEBUG
debug: sets

test: sets
	-for c in $(BINS); do $$c; done

valgrind: debug
	-for c in $(BINS); do $(VALGRIND) $$c; done

sets: $(BINS)


# objects

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ -c $<


# library

$(LIB): $(LIBOBJS)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(LD) -r -o $(OBJDIR)/$(NAME).o $^
	$(AR) rs $@ $(OBJDIR)/$(NAME).o


# binaries

$(BINS): $(BINDIR)/%: $(OBJDIR)/%.o $(LIB)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)


clean:
	$(RM) -r $(BUILDDIR)
