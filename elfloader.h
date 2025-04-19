#ifndef ELFLOADER_H
#define ELFLOADER_H
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <queue>
#include <map>
#include <set>

#include "basicblock.h"
#include "elfloader.h"

void add_symbol_blocks(Elf *elf, std::queue<block_t *> *Q, std::set<block_t *> *blocks, uint64_t text_start, uint64_t text_end, bool reachable_only);
Elf_Data *find_text(Elf *elf, uint64_t *text_start, uint64_t *text_end);
#endif