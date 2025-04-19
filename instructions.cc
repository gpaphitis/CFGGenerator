#include "instructions.h"


bool is_cs_cflow_group(uint8_t g)
{
    return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

bool is_cs_cflow_ins(cs_insn *ins)
{
    for (size_t i = 0; i < ins->detail->groups_count; i++)
    {
        if (is_cs_cflow_group(ins->detail->groups[i]))
        {
            return true;
        }
    }
    return false;
}

bool is_cs_call_ins(cs_insn *ins)
{
    return ins->id == X86_INS_CALL;
}

bool is_cs_unconditional_csflow_ins(cs_insn *ins)
{
    switch (ins->id)
    {
    case X86_INS_JMP:    // Unconditional jump
    case X86_INS_LJMP:   // Far jump
    case X86_INS_RET:    // Near return
    case X86_INS_RETF:   // Far return (16-bit operand)
    case X86_INS_RETFQ:  // Far return (64-bit operand)
    case X86_INS_SYSRET: // Return from syscall
    case X86_INS_IRET:   // Interrupt return (16-bit)
    case X86_INS_IRETD:  // Interrupt return (32-bit)
    case X86_INS_IRETQ:  // Interrupt return (64-bit)
        return true;
    default:
        return false;
    }
}

bool is_cs_conditional_csflow_ins(cs_insn *ins)
{
    switch (ins->id)
    {
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
        return true;
    default:
        return false;
    }
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins)
{
   cs_x86_op *cs_op;

   for (size_t i = 0; i < ins->detail->groups_count; i++)
   {
       if (is_cs_cflow_group(ins->detail->groups[i]))
       {
           for (size_t j = 0; j < ins->detail->x86.op_count; j++)
           {
               cs_op = &ins->detail->x86.operands[j];
               if (cs_op->type == X86_OP_IMM)
                   return cs_op->imm;
           }
       }
   }
   return 0;
}