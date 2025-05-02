#include "cfggenerator.h"

#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

uint64_t counter = 0;

void print_connections(cfg_t *cfg, block_t *block)
{
    for (auto &pair : (cfg->connections))
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

void print_graph(cfg_t *cfg)
{
    printf("GRAPH\n");
    for (block_t *block : cfg->blocks)
    {
        printf("%lu 0x%lx - 0x%lx\n", block->id, block->start_addr, block->end_addr);
        print_connections(cfg, block);
    }
}

void output_cfg(cfg_t *cfg)
{
    output_graph(&(cfg->connections), &(cfg->blocks));
}

void check_correctness(cfg_t *cfg)
{
    for (block_t *block : cfg->blocks)
    {
        for (block_t *other_block : cfg->blocks)
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

block_t *is_start_of_block(cfg_t *cfg, uint64_t target)
{
    for (block_t *block : cfg->blocks)
    {
        if (block->start_addr == target)
            return block;
    }
    return NULL;
}
block_t *is_between_of_block(cfg_t *cfg, uint64_t target)
{
    for (block_t *block : cfg->blocks)
    {
        if (block->start_addr < target && target < block->end_addr)
            return block;
    }
    return NULL;
}

void add_connection(cfg_t *cfg, block_t *from, block_t *to)
{
    auto pair = cfg->connections.find(from);
    if (pair != cfg->connections.end())
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
        cfg->connections.insert({from, std::set<block_t *>{to}});
}
void remove_connection(cfg_t *cfg, block_t *from, block_t *to)
{
    auto pair = cfg->connections.find(from);
    if (pair != cfg->connections.end())
    {
        std::set<block_t *> *block_connections = &pair->second;
        block_connections->erase(to);
    }
}
void switch_connection_origin(cfg_t *cfg, block_t *from, block_t *new_from)
{
    auto pair = cfg->connections.find(from);
    if (pair != cfg->connections.end())
    {
        std::set<block_t *> *block_connections = &(pair->second);
        for (block_t *block : *block_connections)
        {
            add_connection(cfg, new_from, block);
        }
        block_connections->clear();
    }
}

void handle_control_flow(uint64_t target, cfg_t *cfg, std::queue<block_t *> *unexplored_blocks, block_t *block, uint64_t text_start, uint64_t text_end)
{
    block_t *target_block = NULL;
    if ((target_block = is_start_of_block(cfg, target)) != NULL)
    {
        add_connection(cfg, block, target_block);
    }
    else if ((target_block = is_between_of_block(cfg, target)) != NULL) // We have a jump to the middle of a block so we need to split the block
    {
        block_t *second_half = create_basic_block();
        second_half->start_addr = target;
        second_half->end_addr = target_block->end_addr;
        target_block->end_addr = target - 1;
        cfg->blocks.insert(second_half);
        if (second_half->start_addr >= text_start && second_half->end_addr <= text_end)
        {
            unexplored_blocks->push(second_half);
        }
        add_connection(cfg, block, second_half);
        switch_connection_origin(cfg, target_block, second_half);
    }
    else
    {
        target_block = create_basic_block();
        target_block->start_addr = target;
        target_block->end_addr = target;
        cfg->blocks.insert(target_block);
        if (target_block->start_addr >= text_start)
        {
            unexplored_blocks->push(target_block);
        }
        add_connection(cfg, block, target_block);
    }
}

void process_block(csh handle, Elf_Data *text, uint64_t text_start, uint64_t text_end, cfg_t *cfg, std::queue<block_t *> *unexplored_blocks, block_t *block)
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
        size_t len = strlen(cs_ins->mnemonic);
        char *ins_mnemonic = (char *)malloc(len + 1);
        strncpy(ins_mnemonic, cs_ins->mnemonic, len);
        ins_mnemonic[len] = '\0';
        block->instructions.insert({cs_ins->address, ins_mnemonic});
        if (is_cs_cflow_ins(cs_ins) == true)
        {
            block->end_addr = cs_ins->address + cs_ins->size - 1;
            target = get_cs_ins_immediate_target(cs_ins);
            if (target == 0)
                break;
            handle_control_flow(target, cfg, unexplored_blocks, block, text_start, text_end);
            // Conditional branch or a call so we need to add a connection to the fall through path
            if ((is_cs_conditional_csflow_ins(cs_ins) || is_cs_call_ins(cs_ins)) && cs_ins->address + cs_ins->size < text_end)
            {
                handle_control_flow(cs_ins->address + cs_ins->size, cfg, unexplored_blocks, block, text_start, text_end);
            }
            break;
        }
        block_t *next_block = NULL;
        if ((next_block = is_start_of_block(cfg, cs_ins->address + cs_ins->size)) != NULL) // If next instruction is the start of a block then stop
        {
            add_connection(cfg, block, next_block);
            break;
        }
    }

    cs_free(cs_ins, 1);
}

void free_cfg(cfg_t *cfg)
{
    for (block_t *block : cfg->blocks)
    {
        for (auto pair : block->instructions)
            free(pair.second);
        delete block;
    }
    cfg->blocks.clear();
    cfg->connections.clear();
    delete cfg;
}

cfg_t *generate_cfg(csh handle, bool reachable_only)
{
    cfg_t *cfg = new cfg_t();
    std::queue<block_t *> found_blocks;
    std::set<block_t *> closed_blocks;
    uint64_t text_start = 0;
    uint64_t text_end = 0;
    Elf_Data *text = find_text(&text_start, &text_end);

    if (!text)
        DIE("(find_text) %s", elf_errmsg(-1));

    add_symbol_blocks(&found_blocks, &(cfg->blocks), text_start, text_end, reachable_only);
    while (!found_blocks.empty())
    {
        block_t *block = found_blocks.front();
        found_blocks.pop();
        if (closed_blocks.find(block) != closed_blocks.end())
            continue;
        process_block(handle, text, text_start, text_end, cfg, &found_blocks, block);
        closed_blocks.insert(block);
    }
    closed_blocks.clear();
    return cfg;
}