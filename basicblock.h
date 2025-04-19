#ifndef BASICBLOCK_H
#define BASICBLOCK_H
#include <stdlib.h>
#include <stdio.h>
#include <libelf.h>

typedef struct
{
    uint64_t id;
    uint64_t start_addr;
    uint64_t end_addr;
} block_t;

block_t *create_basic_block();

#endif