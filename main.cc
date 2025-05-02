#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "cfggenerator.h"

struct option long_options[] = {
    {"reachable-only", no_argument, 0, 'r'},
    {"full", no_argument, 0, 'r'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

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

    cfg_t *cfg = generate_cfg(handle, reachable_only);
    output_cfg(cfg);

    free_cfg(cfg);
    cs_close(&handle);
    free_elf_loader();

    return 1;
}