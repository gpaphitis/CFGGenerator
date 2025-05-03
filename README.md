# CFG Analyzer
A simple tool that constructs and visualizes the Control Flow Graph (CFG) of an ELF binary, along with basic static analysis features.
It uses [Capstone](http://www.capstone-engine.org/) for disassembly and outputs a `.dot` file for visualization via Graphviz.

## Features
- Constructs the Control Flow Graph (CFG) for either all functions or only those reachable from main
- Outputs a Graphviz-compatible `.dot` file for visualization
- Detects cycles and identifies natural loops in functions
- Detects dead code (unreachable basic blocks from the main function)
- Supports x86_64 ELF binaries

## Dependencies
- [Capstone](http://www.capstone-engine.org/)
- Graphviz (for rendering `.dot` files)

## Compilation
```bash
make
```

## Usage
./cfggenerator [--reachable-only|-r] [--cycles|-c] [--dead-code|-d] [--generate-png|-g] [--help|-h]

## Options
- -r, --reachable-only	Only output blocks reachable from the main function
- -c, --cycles          Performs cycle detection within the CFG and identifies natural loops using dominator-based analysis.
- -d, --dead-code       Outputs basic blocks that are not reachable from the program's main function.
- -g, --generate-png    Automatically renders the generated .dot file into a .png image using Graphviz's dot tool.
- -h, --help	        Show usage information
