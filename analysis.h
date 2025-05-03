#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
#include <stdlib.h>
#include "cfgtypes.h"
#include "elfloader.h"

#include <list>
#include <algorithm>

void detect_cycles(cfg_t *cfg);
void detect_dead_code(cfg_t *cfg);

#endif