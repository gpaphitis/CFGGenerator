#ifndef CFGTYPES_H
#define CFGTYPES_H

#include <queue>
#include <map>
#include <set>
#include <cstdint>

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

struct cfg_t
{
    std::set<block_t *> blocks;
    std::map<block_t *, std::set<block_t *>> connections;
    cfg_t()
    {
    }
};

#endif