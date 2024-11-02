CXX=g++
CXXFLAGS+=-std=c++2a -Wall -Wextra -Wpedantic

BIN_DIR=bin
NAME=minix-disk-util
SRC=src/$(NAME).cpp
BIN=$(BIN_DIR)/$(NAME)

HDD=../example-hdd/hdd0.dsk

.PHONY: all format clean

all: $(BIN_DIR)/ $(BIN) Makefile

%/:
	mkdir -p $@

$(BIN): $(SRC) Makefile
	$(CXX) $(CXXFLAGS) -o $@ $<

format:
	clang-format -i $(SRC)

clean:
	rm -rf $(BIN_DIR)
