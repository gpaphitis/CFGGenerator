#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include "cfggenerator.h"
#include "analysis.h"

struct option long_options[] = {
    {"reachable-only", no_argument, 0, 'r'},
    {"detect-cycles", no_argument, 0, 'c'},
    {"generate-png", no_argument, 0, 'g'},
    {"full", no_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}};

void generate_dot()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        // Fork failed
        perror("Failed generating graph from graph.dot");
        return;
    }
    else if (pid == 0)
    {
        const char *args[] = {"dot","-Tpng", "graph.dot", "-o", "graph.png", nullptr};
        execvp("dot", (char *const *)args);

        perror("Failed generating graph from graph.dot");
        exit(1);
    }
    else
    {
        // Parent process
        wait(NULL); // Wait for child to finish
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

    initialize_elf_loader(argv[1]);

    bool reachable_only = false;
    bool cycle_detection = false;
    bool generate_png = false;
    int opt;
    while ((opt = getopt_long(argc, argv, "rhcfg", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'r':
            reachable_only = true;
            break;
        case 'c':
            cycle_detection = true;
            break;
        case 'g':
            generate_png = true;
            break;
        case 'h':
            printf("Usage: %s ./test_binary [--reachable-only|-r] [--help|-h] [--cycle-detection|-c] [--generate-png|-g]\n", argv[0]);
            exit(0);
        default:
            fprintf(stderr, "Unknown option. Use --help for usage.\n");
            exit(1);
        }
    }

    cfg_t *cfg = generate_cfg(handle, reachable_only);
    output_cfg(cfg);

    if (generate_png)
        generate_dot();

    if (cycle_detection)
        detect_cycles(cfg);

    free_cfg(cfg);
    cs_close(&handle);
    free_elf_loader();

    return 1;
}