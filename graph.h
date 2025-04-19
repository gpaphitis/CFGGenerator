#ifndef GRAPH_H
#define GRAPH_H
#include <stdlib.h>
#include <stdio.h>
#include <gelf.h>
#include <queue>
#include <map>
#include <set>

#include "basicblock.h"

void output_graph(std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks);
#endif