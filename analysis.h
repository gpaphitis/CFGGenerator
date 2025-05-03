#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <stdio.h>
#include <stdlib.h>
#include "cfgtypes.h"

#include <list>
#include <algorithm>

void detect_cycles(cfg_t *cfg);

#endif