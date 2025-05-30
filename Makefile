CC = g++
CFLAGS = -Wall -Werror -g
LDFLAGS = -lelf -lcapstone
SRC = cfggenerator.cc analysis.cc basicblock.cc elfloader.cc instructions.cc graph.cc main.cc
OBJ = $(SRC:.cc=.o)
TARGET = cfganalyzer

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cc
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
	rm *.dot
	rm *.png

.PHONY: all clean