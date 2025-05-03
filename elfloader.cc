#include "elfloader.h"

#define TOOL "elfloader"
#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

static Elf *elf;

void initialize_elf_loader(char *filename)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));
    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(version) %s", elf_errmsg(-1));
}

void add_symbol_blocks(std::queue<block_t *> *Q, std::set<block_t *> *blocks, uint64_t text_start, uint64_t text_end, bool reachable_only)
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
            if (!strcmp("goo", elf_strptr(elf, shdr.sh_link, sym.st_name)))
                printf("Added\n");
            block_t *new_block = create_basic_block();
            new_block->start_addr = sym.st_value;
            new_block->end_addr = sym.st_value;
            Q->push(new_block);
            blocks->insert(new_block);
        }
    }
}

Elf_Data *find_text(uint64_t *text_start, uint64_t *text_end)
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

uint64_t find_main_start()
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
        if (!strcmp("main", elf_strptr(elf, shdr.sh_link, sym.st_name)))
            return sym.st_value;
    }
    return 0;
}

void free_elf_loader()
{
    elf_end(elf);
}