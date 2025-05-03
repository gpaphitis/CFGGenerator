#include "analysis.h"

void find_root_nodes(cfg_t *cfg, std::list<block_t *> *root_nodes)
{
    for (block_t *block : cfg->blocks)
    {
        bool is_root = true;
        for (auto &pair : (cfg->connections))
        {
            std::set<block_t *> block_connections = pair.second;
            auto found = block_connections.find(block);
            if (found != block_connections.end())
                is_root = false;
        }
        if (is_root)
            root_nodes->push_back(block);
    }
}

bool check_if_dominates(cfg_t *cfg, block_t *from, block_t *target)
{
    // Check forward edge
    auto from_pair = cfg->connections.find(from);
    if (from_pair == cfg->connections.end())
        return false;
    std::set<block_t *> from_connections = from_pair->second;
    auto forward_edge = from_connections.find(target);
    if (forward_edge == from_connections.end())
        return false;

    // Check back edge
    auto target_pair = cfg->connections.find(target);
    if (target_pair == cfg->connections.end())
        return false;
    std::set<block_t *> target_connections = target_pair->second;
    auto back_edge = target_connections.find(from);
    if (back_edge == target_connections.end())
        return false;

    // Check if from dominates target
    for (auto &pair : (cfg->connections))
    {
        std::set<block_t *> block_connections = pair.second;
        auto found = block_connections.find(target);
        // If block has connection to target and isn't target from block then it doesn't dominate it
        if (found != block_connections.end() && pair.first != from)
            return false;
    }
    return true;
}

void cycles_DFS(cfg_t *cfg, block_t *curr_node, std::list<block_t *> *branch)
{
    auto map_node = cfg->connections.find(curr_node);
    if (map_node == cfg->connections.end())
        return;
    branch->push_back(curr_node);
    for (block_t *neighbour : map_node->second)
    {
        auto it = std::find(branch->begin(), branch->end(), neighbour);
        if (it != branch->end()) // Neighbour is in active branch
        {
            if (check_if_dominates(cfg, neighbour, curr_node))
                printf(" Natural loop\n");
            else
                printf("Cycle\n");
            printf("\tHeader: B%lu\n", neighbour->id);
            printf("\tBack edge: B%lu -> B%lu\n", curr_node->id, neighbour->id);
            printf("\tBlocks: ");
            for (; it != branch->end(); ++it)
            {
                if (*it == curr_node)
                    printf("B%lu\n\n", (*it)->id);
                else
                    printf("B%lu, ", (*it)->id);
            }
        }
        else
        {
            cycles_DFS(cfg, neighbour, branch);
        }
    }
    branch->remove(curr_node);
    return;
}

void cycles_DFS_wrapper(cfg_t *cfg, block_t *root)
{
    std::list<block_t *> branch;
    cycles_DFS(cfg, root, &branch);
    branch.clear();
}

void detect_cycles(cfg_t *cfg)
{
    std::list<block_t *> root_nodes;

    find_root_nodes(cfg, &root_nodes);

    printf("==================== CYCLES ====================\n");
    for (block_t *block : root_nodes)
    {
        cycles_DFS_wrapper(cfg, block);
    }
    root_nodes.clear();
}

void dead_code_DFS(cfg_t *cfg, block_t *curr_node, std::map<block_t *, bool> *reachable_blocks)
{
    auto reachable_node = reachable_blocks->find(curr_node);
    if (reachable_node == reachable_blocks->end())
        return;
    if (reachable_node->second == true) // Already found block
        return;
    reachable_node->second = true;
    auto map_node = cfg->connections.find(curr_node);
    if (map_node == cfg->connections.end())
        return;
    for (block_t *neighbour : map_node->second)
        dead_code_DFS(cfg, neighbour, reachable_blocks);
}

void detect_dead_code(cfg_t *cfg)
{
    printf("==================== DEAD CODE ====================\n");
    printf("Unreachable Basic Blocks:\n");
    uint64_t main_start = find_main_start();
    if (main_start == 0)
        return;
    block_t *main = NULL;
    std::map<block_t *, bool> reachable_blocks;
    for (block_t *block : cfg->blocks)
    {
        reachable_blocks.insert({block, false});
        if (block->start_addr == main_start)
            main = block;
    }
    dead_code_DFS(cfg, main, &reachable_blocks);
    for (auto pair : reachable_blocks)
    {
        if (!pair.second)
            printf("- B%lu\n", pair.first->id);
    }
    reachable_blocks.clear();
}