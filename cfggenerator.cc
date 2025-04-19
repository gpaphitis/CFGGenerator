
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

#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

typedef struct
{
    uint64_t id;
    uint64_t start_addr;
    uint64_t end_addr;
} block_t;

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

void output_graph(std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks)
{
    FILE *fd = fopen("graph.dot", "w");
    if (fd == NULL)
    {
        perror("Unable to open file");
        return;
    }
    fprintf(fd, "digraph G {\n");
    for (auto &pair : *connections)
    {
        block_t *from_block = pair.first;
        std::set<block_t *> *block_connections = &pair.second;
        for (block_t *connection : *block_connections)
            fprintf(fd, "    %lu -> %lu\n", from_block->id, connection->id);
    }
    fprintf(fd, "}\n");

    // Close the file
    fclose(fd);
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

bool is_cs_call_ins(cs_insn *ins)
{
    return ins->id == X86_INS_CALL;
}

bool is_cs_unconditional_csflow_ins(cs_insn *ins)
{
    switch (ins->id)
    {
    case X86_INS_JMP:    // Unconditional jump
    case X86_INS_LJMP:   // Far jump
    case X86_INS_RET:    // Near return
    case X86_INS_RETF:   // Far return (16-bit operand)
    case X86_INS_RETFQ:  // Far return (64-bit operand)
    case X86_INS_SYSRET: // Return from syscall
    case X86_INS_IRET:   // Interrupt return (16-bit)
    case X86_INS_IRETD:  // Interrupt return (32-bit)
    case X86_INS_IRETQ:  // Interrupt return (64-bit)
        return true;
    default:
        return false;
    }
}

bool is_cs_conditional_csflow_ins(cs_insn *ins)
{
    switch (ins->id)
    {
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
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

void add_symbol_blocks(Elf *elf, std::queue<block_t *> *Q, std::set<block_t *> *blocks, uint64_t text_start, uint64_t text_end, bool reachable_only)
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
            (!strcmp("main", elf_strptr(elf, shdr.sh_link, sym.st_name)) || !reachable_only) &&
            (sym.st_value >= text_start && sym.st_value < text_end))
        {
            block_t *newBlock = (block_t *)malloc(sizeof(block_t));
            newBlock->id = counter++;
            newBlock->start_addr = sym.st_value;
            newBlock->end_addr = sym.st_value;
            Q->push(newBlock);
            blocks->insert(newBlock);
        }
    }
}

Elf_Data *find_text(Elf *elf, uint64_t *text_start, uint64_t *text_end)
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

void handle_control_flow(uint64_t target, std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks, std::queue<block_t *> *unexplored_blocks, block_t *block, uint64_t text_start, uint64_t text_end)
{
    block_t *target_block = NULL;
    if ((target_block = is_start_of_block(blocks, target)) != NULL)
    {
        add_connection(connections, block, target_block);
    }
    else if ((target_block = is_between_of_block(blocks, target)) != NULL) // We have a jump to the middle of a block so we need to split the block
    {
        block_t *second_half = (block_t *)malloc(sizeof(block_t));
        second_half->id = counter++;
        second_half->start_addr = target;
        second_half->end_addr = target_block->end_addr;
        target_block->end_addr = target - 1;
        if (second_half->start_addr >= text_start && second_half->end_addr <= text_end)
        {
            blocks->insert(second_half);
            unexplored_blocks->push(second_half);
        }
        add_connection(connections, block, second_half);
        switch_connection_origin(connections, target_block, second_half);
    }
    else
    {
        target_block = (block_t *)malloc(sizeof(block_t));
        target_block->id = counter++;
        target_block->start_addr = target;
        target_block->end_addr = target;
        if (target_block->start_addr >= text_start)
        {
            blocks->insert(target_block);
            unexplored_blocks->push(target_block);
        }
        add_connection(connections, block, target_block);
    }
}

void disas_r(csh handle, Elf_Data *text, uint64_t text_start, uint64_t text_end, std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks, std::queue<block_t *> *unexplored_blocks, block_t *block)
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
            target = get_cs_ins_immediate_target(cs_ins);
            if (target == 0)
                break;
            handle_control_flow(target, connections, blocks, unexplored_blocks, block, text_start, text_end);
            if (block->start_addr == 0x401100)
                print_connections(connections, block);
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
    block->end_addr = cs_ins->address + cs_ins->size - 1;

    cs_free(cs_ins, 1);
}

void generate_cfg(Elf *elf, csh handle, bool reachable_only)
{
    std::queue<block_t *> found_blocks;
    std::set<block_t *> closed_blocks;
    std::set<block_t *> all_blocks;
    std::map<block_t *, std::set<block_t *>> connections;
    uint64_t text_start = 0;
    uint64_t text_end = 0;
    Elf_Data *text = find_text(elf, &text_start, &text_end);

    if (!text)
        DIE("(find_text) %s", elf_errmsg(-1));

    add_symbol_blocks(elf, &found_blocks, &all_blocks, text_start, text_end, reachable_only);
    while (!found_blocks.empty())
    {
        block_t *block = found_blocks.front();
        found_blocks.pop();
        if (closed_blocks.find(block) != closed_blocks.end())
            continue;
        disas_r(handle, text, text_start, text_end, &connections, &all_blocks, &found_blocks, block);
        closed_blocks.insert(block);
    }
    check_correctness(&all_blocks);
    print_graph(&connections, &all_blocks);
    output_graph(&connections, &all_blocks);
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

    generate_cfg(elf, handle, reachable_only);

    cs_close(&handle);

    return 1;
}
