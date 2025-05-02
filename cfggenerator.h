#ifndef CFGGENERATOR_H
#define CFGGENERATOR_H
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>

#include <queue>
#include <map>
#include <set>

#include "cfgtypes.h"
#include "elfloader.h"
#include "basicblock.h"
#include "instructions.h"
#include "graph.h"

void print_connections(cfg_t *cfg, block_t *block);
void print_graph(cfg_t *cfg);
void output_cfg(cfg_t *cfg);
void free_cfg(cfg_t *cfg);
void check_correctness(cfg_t *cfg);
cfg_t *generate_cfg(csh handle, bool reachable_only);
#endif