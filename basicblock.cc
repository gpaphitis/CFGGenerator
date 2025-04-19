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
    block_t *block = (block_t *)malloc(sizeof(block_t));
    if (block == NULL)
    {
        DIE("(basicblock) %s", "malloc error");
    }
    block->id = counter++;
    return block;
}