#include "graph.h"

void output_graph(std::map<block_t *, std::set<block_t *>> *connections, std::set<block_t *> *blocks)
{
    FILE *fd = fopen("graph.dot", "w");
    if (fd == NULL)
    {
        perror("Unable to open file");
        return;
    }
    fprintf(fd, "digraph G {\n");

    for (block_t *block : *blocks)
    {
        auto pair = connections->find(block);
        if (pair != connections->end())
        {
            std::set<block_t *> *block_connections = &(pair->second);
            if (!block_connections->empty())
            {
                for (block_t *connection : *block_connections)
                    fprintf(fd, "    %lu -> %lu\n", block->id, connection->id);
            }
        }
    }
    fprintf(fd, "\n");
    for (block_t *block : *blocks)
    {
        auto pair = connections->find(block);
        if (pair != connections->end())
        {
            std::set<block_t *> *block_connections = &(pair->second);
            if (block_connections->empty())
                fprintf(fd, "    %lu\n", block->id);
        }
        else
            fprintf(fd, "    %lu\n", block->id);
    }
    fprintf(fd, "}\n");

    // Close the file
    fclose(fd);
}