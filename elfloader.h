#ifndef ELFLOADER_H
#define ELFLOADER_H
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <queue>
#include <map>
#include <set>

#include "cfgtypes.h"
#include "basicblock.h"

void initialize_elf_loader(char *filename);
void add_symbol_blocks(std::queue<block_t *> *Q, std::set<block_t *> *blocks, uint64_t text_start, uint64_t text_end, bool reachable_only);
Elf_Data *find_text(uint64_t *text_start, uint64_t *text_end);
void free_elf_loader();
#endif