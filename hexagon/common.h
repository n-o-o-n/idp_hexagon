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
#ifndef _countof
#  define _countof(array)           (sizeof(array)/sizeof(array[0]))
#endif

// configuration flags
enum {
    HEX_OBRACE_ALONE        = (1 << 0),
    HEX_CBRACE_ALONE        = (1 << 1),
    HEX_BRACES_FOR_SINGLE   = (1 << 2),
    HEX_CR_FOR_DUPLEX       = (1 << 3),
};

uint32_t get_num_ops( uint32_t itype, uint32_t flags );
const char *get_insn_template( uint32_t itype );
ea_t find_packet_end( ea_t ea );
ssize_t loader_elf_machine( linput_t *li, int machine_type, const char **p_procname, proc_def_t **p_pd );
ssize_t emu( const insn_t &insn );
bool hex_is_call_insn( const insn_t &insn );
bool hex_is_ret_insn( const insn_t &insn, bool strict );
ssize_t hex_may_be_func( const insn_t &insn, int state );
ssize_t hex_is_align_insn( ea_t ea );
bool hex_is_jump_func( func_t &pfn, ea_t *jump_target, ea_t *func_pointer );
void out_header( outctx_t &ctx );
void out_footer( outctx_t &ctx );
void out_insn( outctx_t &ctx );
ssize_t out_operand( outctx_t &ctx, const op_t &op );
void hex_create_func_frame( func_t *pfn );
int hex_get_frame_retsize( const func_t &pfn );
int hex_is_sp_based( const insn_t &insn, const op_t &op );
void hex_get_cc_regs( cm_t cc, callregs_t &regs );
bool hex_calc_retloc( cm_t cc, const tinfo_t &type, argloc_t &loc );
bool hex_calc_arglocs( func_type_data_t &fti );
void hex_use_arg_types( ea_t ea, func_type_data_t &fti, funcargvec_t &rargs );
int hex_use_regarg_type( ea_t ea, const funcargvec_t &rargs );

// IDA compatibility stuff
#if IDA_SDK_VERSION < 730
static inline ea_t  inf_get_start_ea()  { return inf.start_ea; }
static inline uchar inf_get_cc_size_l() { return inf.cc.size_l; }
static inline uchar inf_get_cc_size_e() { return inf.cc.size_e; }

#endif

#if IDA_SDK_VERSION < 750

struct procmod_t {};

#endif

//IDAv7.5+ multiple instance support.
//Older versions can instantiate a single object at start and direct all calls to it. TODO: does procmod_t exist in older versions?
struct hexagon_t : public procmod_t {
    //convert all globals to members
    // configuration flags
    uint16_t idpflags = HEX_BRACES_FOR_SINGLE | HEX_CR_FOR_DUPLEX;
    // start of current instruction packet (PC value)
    ea_t s_pkt_start;
    // current instruction address
    ea_t s_insn_ea;

    //convert all funcs using ex-globals to members
    ssize_t idaapi on_event(ssize_t notification_code, va_list va);

    const char* set_idp_options( const char *keyword, int value_type, const void *value );
    //ana-related
    ssize_t ana( insn_t &insn );
    bool decode_single( insn_t &insn, uint32_t word, uint64_t extender );
    uint32_t new_value( uint32_t nt, bool hvx = false );
    void add_pcrel( op_t **ops, int32_t offset );
    uint32_t iclass_1_CJ( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_2_NCJ( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_3_V4LDST( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_4_V2LDST( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_5_J( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_6_CR( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_7_ALU2op( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_8_S2op( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_9_LD( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_9_LD_EXT( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_10_ST( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_10_ST_EXT( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_11_ADDI( uint32_t word, uint64_t extender, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_12_S3op( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_13_ALU64( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_14_M( uint32_t word, uint64_t extender, op_t **ops, uint32_t &flags );
    uint32_t iclass_15_ALU3op( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_5_SYS( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_6_SYS( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_10_SYS( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_1_HVX( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_1_ZReg( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_1_HVX_v68( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_1_HVX_v69( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_2_HVX( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_2_ZReg( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );
    uint32_t iclass_9_HVX( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_9_HMX( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_10_HMX( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_9_DMA( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &/*flags*/ );
    uint32_t iclass_10_DMA( uint32_t word, uint64_t /*extender*/, op_t **ops, uint32_t &flags );

};

#if IDA_SDK_VERSION >= 750

static inline uint16_t out_get_idpflags(outctx_t &ctx) {  return static_cast<hexagon_t *>(ctx.procmod)->idpflags; }
extern int data_id;

#else

extern hexagon_t procmod;
static inline uint16_t out_get_idpflags(outctx_t &ctx) {  return procmod.idpflags; }

#endif
