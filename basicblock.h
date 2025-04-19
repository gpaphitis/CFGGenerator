#ifndef BASICBLOCK_H
#define BASICBLOCK_H
#include <stdlib.h>
#include <stdio.h>
#include <libelf.h>
#include <cstdint>
#include <map>

struct block_t
{
    uint64_t id;
    uint64_t start_addr;
    uint64_t end_addr;
    std::map<uint64_t, char *> instructions;
    block_t()
        : id(0), start_addr(0), end_addr(0)
    {
    }
};

block_t *create_basic_block();

#endif