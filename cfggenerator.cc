
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

#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

enum bb_status
{
    UNSEEN,
    ENQUEUED,
    SEEN
};

typedef struct
{
    long start_addr;
    long end_addr;
} block_t;

/* Instruction classification.  */
bool is_cs_cflow_group(uint8_t g)
{
    return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

bool is_cs_cflow_ins(cs_insn *ins)
{
    for (size_t i = 0; i < ins->detail->groups_count; i++)
    {
        if (is_cs_cflow_group(ins->detail->groups[i]))
        {
            return true;
        }
    }
    return false;
}

bool is_cs_unconditional_csflow_ins(cs_insn *ins)
{
    switch (ins->id)
    {
    case X86_INS_JMP:
    case X86_INS_LJMP:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return true;
    default:
        return false;
    }
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins)
{
    cs_x86_op *cs_op;

    for (size_t i = 0; i < ins->detail->groups_count; i++)
    {
        if (is_cs_cflow_group(ins->detail->groups[i]))
        {
            for (size_t j = 0; j < ins->detail->x86.op_count; j++)
            {
                cs_op = &ins->detail->x86.operands[j];
                if (cs_op->type == X86_OP_IMM)
                    return cs_op->imm;
            }
        }
    }
    return 0;
}

void read_symbol_table(Elf *elf, std::queue<block_t *> *Q, std::set<block_t *> *blocks, long unsigned text_start, long unsigned text_end)
{
    Elf_Scn *scn = NULL;
    Elf_Scn *symtab = NULL;
    Elf_Data *data;
    GElf_Shdr shdr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));

        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
        {
            symtab = scn;
            break;
        }
    }

    /* Get the descriptor.  */
    if (gelf_getshdr(symtab, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(symtab, NULL);
    int count = shdr.sh_size / shdr.sh_entsize;

    for (int i = 0; i < count; ++i)
    {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC &&
            (sym.st_value >= text_start && sym.st_value < text_end))
        {
            fprintf(stderr, "Queueing %s at %016lx.\n", elf_strptr(elf, shdr.sh_link, sym.st_name), sym.st_value);
            block_t *newBlock = (block_t *)malloc(sizeof(block_t));
            newBlock->start_addr = sym.st_value;
            Q->push(newBlock);
            blocks->insert(newBlock);
        }
    }
}

Elf_Data *find_text(Elf *elf, long unsigned *text_start, long unsigned *text_end)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    Elf_Data *data = NULL;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));

        /* Locate .text  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text"))
        {
            data = elf_getdata(scn, data);
            if (!data)
                DIE("(getdata) %s", elf_errmsg(-1));

            *text_start = shdr.sh_addr;
            *text_end = *text_start + shdr.sh_size;

            return (data);
        }
    }
    return NULL;
}

void print_ins(cs_insn *ins)
{

    fprintf(stderr, "0x%016lx:\t%s\t\t%s\n", ins->address, ins->mnemonic, ins->op_str);
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
        if (block->start_addr < target && block->end_addr > target)
            return block;
    }
    return NULL;
}

void add_connection(std::map<block_t *, std::set<block_t *>> *connections, block_t *from, block_t *to)
{
    for (auto &pair : *connections)
    {
        block_t *from_block = pair.first;
        if (from_block == from)
        {
            std::set<block_t *> *block_connections = &pair.second;
            for (block_t *block : *block_connections)
            {
                if (block == to)
                    return;
            }
            block_connections->insert(to);
            return;
        }
    }
    connections->insert({from, std::set<block_t *>{to}});
}
void remove_connection(std::map<block_t *, std::set<block_t *>> *connections, block_t *from, block_t *to)
{
    for (auto &pair : *connections)
    {
        block_t *from_block = pair.first;
        if (from_block == from)
        {
            std::set<block_t *> *block_connections = &pair.second;
            block_connections->erase(to);
        }
    }
}
void switch_connection_origin(std::map<block_t *, std::set<block_t *>> *connections, block_t *from, block_t *new_from)
{
    for (auto &pair : *connections)
    {
        block_t *from_block = pair.first;
        if (from_block == from)
        {
            std::set<block_t *> *block_connections = &pair.second;
            for (block_t *block : *block_connections)
            {
                add_connection(connections, new_from, block);
                block_connections->erase(block);
            }
        }
    }
}

void handle_control_flow(uint64_t target, std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks, std::queue<block_t *> *unexplored_blocks, block_t *block)
{
    block_t *target_block = NULL;
    if ((target_block = is_start_of_block(blocks, target)) != NULL)
    {
        add_connection(connections, block, target_block);
    }
    else if ((target_block = is_between_of_block(blocks, target)) != NULL) // We have a jump to the middle of a block so we need to split the block
    {
        block_t *second_half = (block_t *)malloc(sizeof(block_t));
        blocks->insert(second_half);
        unexplored_blocks->push(second_half);
        second_half->start_addr = target;
        second_half->end_addr = target_block->end_addr;
        target_block->end_addr = target;
        add_connection(connections, block, second_half);
        switch_connection_origin(connections, target_block, second_half);
    }
    else
    {
        target_block = (block_t *)malloc(sizeof(block_t));
        target_block->start_addr = target;
        blocks->insert(target_block);
        unexplored_blocks->push(target_block);
    }
}

void disas_r(csh handle, Elf_Data *text, long text_start, long text_end, std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks, std::queue<block_t *> *unexplored_blocks, block_t *block)
{

    Elf *elf;
    uint64_t addr, offset, target;
    const uint8_t *pc;
    size_t n;
    cs_insn *cs_ins;

    offset = addr - text_start;
    pc = (const unsigned char *)text->d_buf;
    pc += offset;
    n = text_end - text_start;

    cs_ins = cs_malloc(handle);
    fprintf(stderr, "Starting at 0x%016lx\n", addr);
    while (cs_disasm_iter(handle, &pc, &n, &addr, cs_ins))
    {
        if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0)
            break;

        if (is_cs_unconditional_csflow_ins(cs_ins) || is_cs_cflow_ins(cs_ins))
        {
            target = get_cs_ins_immediate_target(cs_ins);
            handle_control_flow(target, connections, blocks, unexplored_blocks, block);
            // Conditional branch so we need to add a connection to the fall through path
            if (is_cs_cflow_ins(cs_ins))
                handle_control_flow(cs_ins->address + cs_ins->size, connections, blocks, unexplored_blocks, block);
            break;
        }
    }

    cs_free(cs_ins, 1);
}

void generate_cfg(Elf *elf, csh handle)
{
    std::queue<block_t *> found_blocks;
    std::set<block_t *> closed_blocks;
    std::set<block_t *> allBlocks;
    std::map<block_t *, std::set<block_t *>> connections;
    long unsigned text_start = 0;
    long unsigned text_end = 0;
    Elf_Data *text = find_text(elf, &text_start, &text_end);

    if (!text)
        DIE("(find_text) %s", elf_errmsg(-1));

    read_symbol_table(elf, &found_blocks, &allBlocks, text_start, text_end);
    while (!found_blocks.empty())
    {
        block_t *block = found_blocks.front();
        found_blocks.pop();
        if (closed_blocks.find(block) != closed_blocks.end())
            continue;
        disas_r(handle, text, text_start, text_end, &connections, &allBlocks, &found_blocks, block);
        closed_blocks.insert(block);
    }
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
    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(argv[1], O_RDONLY);

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    generate_cfg(elf, handle);
    // disas_r(argv[1], handle);

    cs_close(&handle);

    return 1;
}
