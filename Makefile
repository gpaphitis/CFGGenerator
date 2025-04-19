CC = g++
CFLAGS = -Wall -Werror -g -DDEBUG
LDFLAGS = -lelf -lcapstone
SRC = cfggenerator.cc basicblock.cc elfloader.cc instructions.cc graph.cc
OBJ = $(SRC:.cc=.o)
TARGET = cfggenerator

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean