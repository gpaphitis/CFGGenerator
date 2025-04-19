#include "basicblock.h"

#define TOOL "basicblock"
#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

static uint64_t counter = 0;

block_t *create_basic_block()
{
    block_t *block = new block_t();
    block->id = counter++;
    return block;
}