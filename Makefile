.POSIX:
NAME      = cryptopals
SRC_DIR   = cryptopals
BUILD_DIR = build
OBJ_DIR   = $(BUILD_DIR)/obj
LIB_DIR   = $(BUILD_DIR)/lib
BIN_DIR   = $(BUILD_DIR)/bin

CC        = cc
CFLAGS    = -std=c89 -Wall -Wextra -Werror -pedantic -O -I./
LDFLAGS   = -O
LDLIBS    = -lm -lssl -lcrypto
VALGRIND  = valgrind

LIB       = $(LIB_DIR)/$(NAME).a
LIB_SRCS  = $(wildcard $(SRC_DIR)/*.c)
LIB_OBJS  = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(LIB_SRCS)))

SETS      = set01 set02


all: sets

debug: CFLAGS += -DDEBUG
debug: sets

test: sets
	-for c in $(BIN_DIR)/*; do $$c; done

valgrind: debug
	-for c in $(BIN_DIR)/*; do $(VALGRIND) $$c; done

sets: $(SETS)


# library

$(LIB): $(LIB_OBJS)
	@[ -d $(LIB_DIR) ] || mkdir -p $(LIB_DIR)
	$(LD) -r -o $(OBJ_DIR)/$(NAME).o $(LIB_OBJS)
	ar rvs $@ $(OBJ_DIR)/$(NAME).o


# objects

$(LIB_OBJS): $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@


# set 01

SET01_SRCS = $(wildcard $(SRC_DIR)/set01/*.c)
SET01_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(SET01_SRCS)))
SET01      = $(notdir $(basename $(SET01_SRCS)))

set01: $(SET01)

$(SET01): %: $(OBJ_DIR)/%.o $(LIB) $(LDLIBS)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(SET01_OBJS): $(OBJ_DIR)/%.o: $(SRC_DIR)/set01/%.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $^


# set 02

SET02_SRCS = $(wildcard $(SRC_DIR)/set02/*.c)
SET02_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(SET02_SRCS)))
SET02      = $(notdir $(basename $(SET02_SRCS)))

set02: $(SET02)

$(SET02): %: $(OBJ_DIR)/%.o $(LIB) $(LDLIBS)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(SET02_OBJS): $(OBJ_DIR)/%.o: $(SRC_DIR)/set02/%.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $^


.PHONY: all test debug valgrind sets $(SETS) clean $(LDLIBS)

clean:
	rm -rf $(BUILD_DIR)
