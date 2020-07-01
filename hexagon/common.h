/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#pragma once
#include "../idaidp.hpp"
#include "fixup.hpp"
#include "frame.hpp"
#include "ieee.h"
#include "typeinf.hpp"
#include "ins.h"

#define IN_RANGE(u,lo,hi)           (uint32_t((u) - (lo)) <= ((hi) - (lo)))

// configuration flags
extern uint16_t idpflags;
enum {
    HEX_OBRACE_ALONE        = (1 << 0),
    HEX_CBRACE_ALONE        = (1 << 1),
    HEX_BRACES_FOR_SINGLE   = (1 << 2),
    HEX_CR_FOR_DUPLEX       = (1 << 3),
};

uint32_t get_num_ops( uint32_t itype, uint32_t flags );
const char *get_insn_template( uint32_t itype );
ssize_t loader_elf_machine( linput_t *li, int machine_type, const char **p_procname, proc_def_t **p_pd );
ssize_t ana( insn_t &insn );
ssize_t emu( const insn_t &insn );
bool hex_is_call_insn( const insn_t &insn );
bool hex_is_ret_insn( const insn_t &insn, bool strict );
ssize_t hex_is_align_insn( ea_t ea );
bool hex_is_jump_func( func_t &pfn, ea_t *jump_target, ea_t *func_pointer );
void out_header( outctx_t &ctx );
void out_footer( outctx_t &ctx );
void out_insn( outctx_t &ctx );
ssize_t out_operand( outctx_t &ctx, const op_t &op );
void hex_create_func_frame( func_t *pfn );
int hex_is_sp_based( const insn_t &insn, const op_t &op );
