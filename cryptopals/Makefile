.POSIX:
NAME      = cryptopals
INCLUDE   = include
SRC_DIR   = src
BUILD_DIR = build
OBJ_DIR   = $(BUILD_DIR)/obj
BIN_DIR   = $(BUILD_DIR)/bin

CC        = cc
CFLAGS    = -Wall -Wextra -Werror -O --std=c99 -I$(INCLUDE)
LDFLAGS   = -O
LDLIBS    = -lm

LIB       = $(BIN_DIR)/$(NAME).a
LIB_OBJS  = $(OBJ_DIR)/base64.o \
			$(OBJ_DIR)/hex.o \
			$(OBJ_DIR)/score.o

SETS      = set01
CS        = c01 c02 c03 c04 c05


all: sets

debug: CFLAGS += -DDEBUG
debug: sets

sets: $(SETS)


# library

$(LIB): $(LIB_OBJS)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(LD) -r -o $(OBJ_DIR)/$(NAME).o $(LIB_OBJS)
	ar rvs $@ $(OBJ_DIR)/$(NAME).o


# objects

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@


# set 01

set01: c01 c02 c03 c04 c05

c01: $(OBJ_DIR)/c01.o $(LIB)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(OBJ_DIR)/c01.o: $(SRC_DIR)/set01/c01.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $<

c02: $(OBJ_DIR)/c02.o $(LIB)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(OBJ_DIR)/c02.o: $(SRC_DIR)/set01/c02.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $<

c03: $(OBJ_DIR)/c03.o $(LIB)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(OBJ_DIR)/c03.o: $(SRC_DIR)/set01/c03.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $<

c04: $(OBJ_DIR)/c04.o $(LIB)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(OBJ_DIR)/c04.o: $(SRC_DIR)/set01/c04.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $<

c05: $(OBJ_DIR)/c05.o $(LIB)
	@[ -d $(BIN_DIR) ] || mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $^

$(OBJ_DIR)/c05.o: $(SRC_DIR)/set01/c05.c
	@[ -d $(OBJ_DIR) ] || mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -o $@ -c $<


clean:
	rm -rf $(BUILD_DIR)
