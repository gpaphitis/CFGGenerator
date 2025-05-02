#include "graph.h"

void output_graph(cfg_t *cfg)
{
    FILE *fd = fopen("graph.dot", "w");
    if (fd == NULL)
    {
        perror("Unable to open file");
        return;
    }
    fprintf(fd, "digraph G {    \nnode [shape=plaintext fontname=\"Courier\"];\n");

    // Print block labels
    for (block_t *block : cfg->blocks)
    {
        fprintf(fd, "BB%lu [label=<\n    <TABLE BORDER=\"1\" CELLBORDER=\"1\" CELLSPACING=\"0\">\n        <TR><TD ALIGN=\"CENTER\"><B>BB%lu:</B></TD></TR>\n", block->id, block->id);
        for (auto pair : block->instructions)
        {
            fprintf(fd, "        <TR><TD ALIGN=\"LEFT\">0x%lx: %s</TD></TR>\n", pair.first, pair.second);
        }
        fprintf(fd, "    </TABLE>\n>];\n");
    }
    fprintf(fd, "\n");

    // Print blocks with connections
    for (block_t *block : cfg->blocks)
    {
        auto pair = cfg->connections.find(block);
        if (pair != cfg->connections.end())
        {
            std::set<block_t *> *block_connections = &(pair->second);
            if (!block_connections->empty())
            {
                for (block_t *connection : *block_connections)
                    fprintf(fd, "    BB%lu -> BB%lu\n", block->id, connection->id);
            }
        }
    }
    fprintf(fd, "\n");

    // Print blocks without connections
    for (block_t *block : cfg->blocks)
    {
        auto pair = cfg->connections.find(block);
        if (pair != cfg->connections.end())
        {
            std::set<block_t *> *block_connections = &(pair->second);
            if (block_connections->empty())
                fprintf(fd, "    BB%lu\n", block->id);
        }
        else
            fprintf(fd, "    BB%lu\n", block->id);
    }
    fprintf(fd, "}\n");

    // Close the file
    fclose(fd);
}