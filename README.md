# CFG Visualizer
A simple tool that constructs Control Flow Graph (CFG) of ELF binaries.  

## Features
- Disassembles using [Capstone](http://www.capstone-engine.org/)
- Supports x86_64 binaries (ELF format)

## Dependencies
- libcapstone2

## Compilation
g++ -Wall -Werror cfggenerator.cc -lcapstone -lelf -o cfggenerator

## Usage
./cfggenerator ./test_binary