# CFG Visualizer
A simple tool that constructs and visualizes the Control Flow Graph (CFG) of an ELF binary.  
It uses [Capstone](http://www.capstone-engine.org/) for disassembly and outputs a `.dot` file for visualization via Graphviz.

## Features
- Constructs the Control Flow Graph (CFG) for either all functions or only those reachable from main
- Outputs a Graphviz-compatible `.dot` file for visualization
- Supports x86_64 binaries (ELF format)

## Dependencies
- [Capstone](http://www.capstone-engine.org/)
- Graphviz (for rendering `.dot` files)

## Compilation
```bash
make
```

## Usage
./a.out ./test_binary [--reachable-only|-r] [--help|-h]

## Options
- -r, --reachable-only	Only output blocks reachable from main
- -h, --help	Show usage information
