#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <capstone/capstone.h>

bool is_cs_cflow_ins(cs_insn *ins);
bool is_cs_call_ins(cs_insn *ins);
bool is_cs_unconditional_csflow_ins(cs_insn *ins);
bool is_cs_conditional_csflow_ins(cs_insn *ins);
uint64_t get_cs_ins_immediate_target(cs_insn *ins);

#endif