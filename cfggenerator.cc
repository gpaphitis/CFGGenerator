
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>

#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

#include <queue>
#include <map>
#include <set>

#include <getopt.h>

#include "elfloader.h"
#include "basicblock.h"
#include "instructions.h"
#include "graph.h"

#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

struct option long_options[] = {
    {"reachable-only", no_argument, 0, 'r'},
    {"full", no_argument, 0, 'r'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

uint64_t counter = 0;

void print_connections(std::map<block_t *, std::set<block_t *>> *connections, block_t *block)
{
    for (auto &pair : *connections)
    {
        block_t *from_block = pair.first;
        if (from_block == block)
        {
            std::set<block_t *> *block_connections = &pair.second;
            for (block_t *connection : *block_connections)
                printf("\t%lu 0x%lx - 0x%lx\n", connection->id, connection->start_addr, connection->end_addr);
            return;
        }
    }
}

void print_graph(std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks)
{
    printf("GRAPH\n");
    for (block_t *block : *blocks)
    {
        printf("%lu 0x%lx - 0x%lx\n", block->id, block->start_addr, block->end_addr);
        print_connections(connections, block);
    }
}

void check_correctness(std::set<block_t *> *blocks)
{
    for (block_t *block : *blocks)
    {
        for (block_t *other_block : *blocks)
        {
            if (block != other_block &&
                ((block->start_addr >= other_block->start_addr && block->start_addr <= other_block->end_addr) ||
                 (block->end_addr >= other_block->start_addr && block->end_addr <= other_block->end_addr)))
            {
                printf("Error\n");
                printf("%lx - %lx\n", block->start_addr, block->end_addr);
                printf("%lx - %lx\n", other_block->start_addr, other_block->end_addr);
            }
        }
    }
}

block_t *is_start_of_block(std::set<block_t *> *blocks, uint64_t target)
{
    for (block_t *block : *blocks)
    {
        if (block->start_addr == target)
            return block;
    }
    return NULL;
}
block_t *is_between_of_block(std::set<block_t *> *blocks, uint64_t target)
{
    for (block_t *block : *blocks)
    {
        if (block->start_addr < target && target < block->end_addr)
            return block;
    }
    return NULL;
}

void add_connection(std::map<block_t *, std::set<block_t *>> *connections, block_t *from, block_t *to)
{
    auto pair = connections->find(from);
    if (pair != connections->end())
    {
        std::set<block_t *> *block_connections = &(pair->second);
        for (block_t *block : *block_connections)
        {
            if (block == to)
                return;
        }
        block_connections->insert(to);
    }
    else // Block's first connection
        connections->insert({from, std::set<block_t *>{to}});
}
void remove_connection(std::map<block_t *, std::set<block_t *>> *connections, block_t *from, block_t *to)
{
    auto pair = connections->find(from);
    if (pair != connections->end())
    {
        std::set<block_t *> *block_connections = &pair->second;
        block_connections->erase(to);
    }
}
void switch_connection_origin(std::map<block_t *, std::set<block_t *>> *connections, block_t *from, block_t *new_from)
{
    auto pair = connections->find(from);
    if (pair != connections->end())
    {
        std::set<block_t *> *block_connections = &(pair->second);
        for (block_t *block : *block_connections)
        {
            add_connection(connections, new_from, block);
        }
        block_connections->clear();
    }
}

void handle_control_flow(uint64_t target, std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks, std::queue<block_t *> *unexplored_blocks, block_t *block, uint64_t text_start, uint64_t text_end)
{
    block_t *target_block = NULL;
    if ((target_block = is_start_of_block(blocks, target)) != NULL)
    {
        add_connection(connections, block, target_block);
    }
    else if ((target_block = is_between_of_block(blocks, target)) != NULL) // We have a jump to the middle of a block so we need to split the block
    {
        block_t *second_half = create_basic_block();
        second_half->start_addr = target;
        second_half->end_addr = target_block->end_addr;
        target_block->end_addr = target - 1;
        blocks->insert(second_half);
        if (second_half->start_addr >= text_start && second_half->end_addr <= text_end)
        {
            unexplored_blocks->push(second_half);
        }
        add_connection(connections, block, second_half);
        switch_connection_origin(connections, target_block, second_half);
    }
    else
    {
        target_block = create_basic_block();
        target_block->start_addr = target;
        target_block->end_addr = target;
        blocks->insert(target_block);
        if (target_block->start_addr >= text_start)
        {
            unexplored_blocks->push(target_block);
        }
        add_connection(connections, block, target_block);
    }
}

void process_block(csh handle, Elf_Data *text, uint64_t text_start, uint64_t text_end, std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks, std::queue<block_t *> *unexplored_blocks, block_t *block)
{
    uint64_t addr, offset, target;
    const uint8_t *pc;
    size_t n;
    cs_insn *cs_ins;

    addr = block->start_addr;
    offset = addr - text_start;
    pc = (const unsigned char *)text->d_buf;
    pc += offset;
    n = text_end - addr;

    cs_ins = cs_malloc(handle);
    while (cs_disasm_iter(handle, &pc, &n, &addr, cs_ins))
    {
        if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0)
            break;
        if (is_cs_cflow_ins(cs_ins) == true)
        {
            block->end_addr = cs_ins->address + cs_ins->size - 1;
            target = get_cs_ins_immediate_target(cs_ins);
            if (target == 0)
                break;
            handle_control_flow(target, connections, blocks, unexplored_blocks, block, text_start, text_end);
            // Conditional branch or a call so we need to add a connection to the fall through path
            if ((is_cs_conditional_csflow_ins(cs_ins) || is_cs_call_ins(cs_ins)) && cs_ins->address + cs_ins->size < text_end)
            {
                handle_control_flow(cs_ins->address + cs_ins->size, connections, blocks, unexplored_blocks, block, text_start, text_end);
            }
            break;
        }
        if (is_start_of_block(blocks, cs_ins->address + cs_ins->size)) // If next instruction is the start of a block then stop
            break;
    }
    // block->end_addr = cs_ins->address + cs_ins->size - 1;

    cs_free(cs_ins, 1);
}

void free_blocks(std::set<block_t *> *blocks)
{
    for (block_t *block : *blocks)
        free(block);
}

void generate_cfg(csh handle, bool reachable_only)
{
    std::queue<block_t *> found_blocks;
    std::set<block_t *> closed_blocks;
    std::set<block_t *> all_blocks;
    std::map<block_t *, std::set<block_t *>> connections;
    uint64_t text_start = 0;
    uint64_t text_end = 0;
    Elf_Data *text = find_text(&text_start, &text_end);

    if (!text)
        DIE("(find_text) %s", elf_errmsg(-1));

    add_symbol_blocks(&found_blocks, &all_blocks, text_start, text_end, reachable_only);
    while (!found_blocks.empty())
    {
        block_t *block = found_blocks.front();
        found_blocks.pop();
        if (closed_blocks.find(block) != closed_blocks.end())
            continue;
        process_block(handle, text, text_start, text_end, &connections, &all_blocks, &found_blocks, block);
        closed_blocks.insert(block);
    }
    check_correctness(&all_blocks);
#ifdef DEBUG
    print_graph(&connections, &all_blocks);
#endif
    output_graph(&connections, &all_blocks);
    free_blocks(&all_blocks);
    closed_blocks.clear();
    all_blocks.clear();
    connections.clear();
}

int main(int argc, char *argv[])
{

    /* Initialize the engine.  */
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    /* detail mode.  */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    initialize_elf_loader(argv[1]);

    bool reachable_only = false;
    int opt;
    while ((opt = getopt_long(argc, argv, "rh", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'r':
            reachable_only = true;
            break;
        case 'h':
            printf("Usage: %s ./test_binary [--reachable-only|-r] [--help|-h]\n", argv[0]);
            exit(0);
        default:
            fprintf(stderr, "Unknown option. Use --help for usage.\n");
            exit(1);
        }
    }

    generate_cfg(handle, reachable_only);

    cs_close(&handle);
    free_elf_loader();

    return 1;
}
