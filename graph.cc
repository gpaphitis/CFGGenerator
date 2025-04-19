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