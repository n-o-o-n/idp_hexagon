/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#pragma once

/*
  Instructions are stored as usual, except for these special cases:
  a) duplex instructions
  .itype[7:0] = 1st sub-instruction, .itype[15:8] = 2nd sub-instruction, .flags |= INSN_DUPLEX
  The 1st sub-instruction flags are stored in .auxpref_u16[0] and .segpref.
  The 2nd sub-instruction flags are stored in .auxpref_u16[1] and .insnpref.
  b) if the instruction is predicated, i.e. it has `if (condition)`,
     then first one or two operands are used for the predicate.
*/
enum {
    // operand types
    // o_mem corresponds to .............. memXX(##u32)
    // o_displ corresponds to ............ memXX(Rs + #s11) or memXX(gp + #u16)
    o_mem_abs_set     = o_idpspec0,     // memXX(Re=##u32)
    o_mem_abs_off,                      // memXX(Ru << #u2 + ##u32)
    o_mem_ind_off,                      // memXX(Rs + Ru << #u2)
    o_mem_inc_imm,                      // memXX(Rx++#s4)
    o_mem_inc_reg,                      // memXX(Rx++Mu)
    o_mem_circ_imm,                     // memXX(Rx++#s4:circ(Mu))
    o_mem_circ_reg,                     // memXX(Rx++I:circ(Mu))
    o_mem_inc_brev,                     // memXX(Rx++Mu:brev)
    o_mem_locked,                       // memXX_locked(Rs[,Pd])
    o_reg_off,                          // Rs + #u14
};

enum {
    // operand type o_reg:
#define REG_R(v)     (REG_R0 + (v))
#define REG_P(v)     (REG_P0 + (v))
#define REG_V(v)     (REG_V0 + (v))
#define REG_Q(v)     (REG_Q0 + (v))
#define REG_C(v)     (REG_C0 + (v))
#define REG_G(v)     (REG_G0 + (v))
#define REG_S(v)     (REG_S0 + (v))
    // general registers
    REG_R0          = 0,                // scalar registers
    REG_SP          = REG_R(29),        // stack pointer
    REG_FP          = REG_R(30),        // frame pointer
    REG_LR          = REG_R(31),        // return address
    REG_P0          = REG_R0 + 32,      // scalar predicates
    REG_V0          = REG_P0 + 4,       // vector registers (TODO: can be reversed!)
    REG_Q0          = REG_V0 + 32,      // vector predicates
    REG_Z           = REG_Q0 + 4,       // 2048 bits regsiter for NN
    REG_VTMP        = REG_Z + 1,        // virtual register for temporary loads
    // user mode control registers
    REG_C0          = REG_VTMP + 1,
    REG_M0          = REG_C(6),         // modifier registers
    REG_M1          = REG_C(7),         // modifier registers
    REG_PC          = REG_C(9),         // program counter
    REG_GP          = REG_C(11),        // global pointer
    // guest mode control registers
    REG_G0          = REG_C0 + 32,
    // monitor mode control registers
    REG_S0          = REG_G0 + 32,
    REG_NUM         = REG_S0 + 128,

    // register flags (stored in .specval)
    REG_DOUBLE      = (1  << 0),        // pair of registers (r1:0 or v1:0)
    REG_QUAD        = (1  << 1),        // four HVX registers (v3:0)
    // register prefixes
    REG_PRE_NONE    = (0  << 2),
    REG_PRE_NOT     = (1  << 2),        // !
    REG_PRE_NEG     = (2  << 2),        // ~
    REG_PRE         = (3  << 2),
    // register postfixes
    REG_POST_NONE   = (0  << 4),
    REG_POST_NEW    = (1  << 4),        // .new
    REG_POST_CUR    = (2  << 4),        // .cur
    REG_POST_TMP    = (3  << 4),        // .tmp
    REG_POST_LO     = (4  << 4),        // .l
    REG_POST_HI     = (5  << 4),        // .h
    REG_POST_CONJ   = (6  << 4),        // *
    REG_POST_B      = (7  << 4),        // .b
    REG_POST_H      = (8  << 4),        // .h
    REG_POST_W      = (9  << 4),        // .w
    REG_POST_UB     = (10 << 4),        // .ub
    REG_POST_UH     = (11 << 4),        // .uh
    REG_POST_UW     = (12 << 4),        // .uw
    REG_POST_N      = (13 << 4),        // .n (nibble)
    REG_POST_C      = (14 << 4),        // .c (crumb)
    REG_POST_MASK   = (15 << 4),
    REG_POST_SHIFT  = 4,
    REG_POST_INC    = (16 << 4),        // ...++
};

static __inline uint32_t reg_op_flags( const op_t &op )
{
    return op.specval;
}

enum {
    // operand type o_mem or o_mem_xxx:
    // memory target type (stored in .specflag1)
    MEM_B           = 0,                // memb
    MEM_BH          = 1,                // membh
    MEM_UB          = 2,                // memub
    MEM_UBH         = 3,                // memubh
    MEM_H           = 4,                // memh
    MEM_UH          = 5,                // memuh
    MEM_W           = 6,                // memw
    MEM_D           = 7,                // memd
    MEM_V           = 8,                // vmem
    MEM_VNT         = 9,                // vmem():nt
    MEM_VU          = 10,               // vmemu
    MEM_TYPE_MASK   = 0x0F,
    MEM_FIFO        = 0x10,             // memX_fifo
    MEM_LOCKED      = 0x20,             // memX_locked
};

static __inline uint32_t mem_op_type( const op_t &op )
{
    return op.specflag1;
}

enum {
    // operand type o_imm:
    // immediate value flags (stored in .specflag1)
    IMM_SIGNED      = (1 << 0),
    IMM_EXTENDED    = (1 << 1),
    IMM_PCREL       = (1 << 2),
};

static __inline uint32_t imm_op_flags( const op_t &op )
{
    return op.specflag1;
}

enum {
    // instruction flags, stored as usual in .flags
    INSN_EXTENDED   = (1 << 2),         // has extender word
    INSN_DUPLEX     = (1 << 3),         // this is duplex
    INSN_PKT_BEG    = (1 << 4),         // start of packet
    INSN_PKT_END    = (1 << 5),         // end of packet
    INSN_ENDLOOP0   = (1 << 6),         // inner loop end
    INSN_ENDLOOP1   = (1 << 7),         // outer loop end
    INSN_ENDLOOP01  = INSN_ENDLOOP0 | INSN_ENDLOOP1,

    // all other flags are stored in .auxpref_u16[*] and .segpref/.insnpref
    // instruction predicates
    PRED_NONE       = (0  << 0),        // no predicate
    PRED_REG        = (1  << 0),        // pred[.new]
    PRED_EQ         = (2  << 0),        // cmp.eq(a,b)
    PRED_GT         = (3  << 0),        // cmp.gt(a,b)
    PRED_GTU        = (4  << 0),        // cmp.gtu(a,b)
    PRED_BS0        = (5  << 0),        // tstbit(Ns.new,#0)
    PRED_NE0        = (6  << 0),        // Rs!=#0
    PRED_GE0        = (7  << 0),        // Rs>=#0
    PRED_EQ0        = (8  << 0),        // Rs==#0
    PRED_LE0        = (9  << 0),        // Rs<=#0
    PRED_NOT        = 8,                // this is not a bitmask!
    PRED_NE         = (10 << 0),        // !cmp.eq(a,b)
    PRED_LE         = (11 << 0),        // !cmp.gt(a,b)
    PRED_LEU        = (12 << 0),        // !cmp.gtu(a,b)
    PRED_BC0        = (13 << 0),        // !tstbit(Ns.new,#0)
    PRED_MASK       = (15 << 0),

    // instruction assignment type (=)
    IAT_ASS         = (0 << 4),         // dst =  insn {default}
    IAT_NOT         = (1 << 4),         // dst = !insn
    IAT_ADD         = (2 << 4),         // dst += insn
    IAT_SUB         = (3 << 4),         // dst -= insn
    IAT_AND         = (4 << 4),         // dst &= insn
    IAT_OR          = (5 << 4),         // dst |= insn
    IAT_XOR         = (6 << 4),         // dst ^= insn
    IAT_MASK        = (7 << 4),
    IAT_SHIFT       = 4,

    // instruction postfix
    IPO_NONE        = (0  << 7),
    IPO_LS1         = (1  << 7),        // :<<1
    IPO_LS1_RND     = (2  << 7),        // :<<1:rnd
    IPO_LS1_RND_SAT = (3  << 7),        // :<<1:rnd:sat
    IPO_LS1_RND_SAT_SHIFT = (4  << 7),  // :<<1:rnd:sat:shift
    IPO_LS1_SAT     = (5  << 7),        // :<<1:sat
    IPO_LS1_SAT_SHIFT = (6  << 7),      // :<<1:sat:shift
    IPO_LS16        = (7  << 7),        // :<<16
    IPO_CARRY       = (8  << 7),        // :carry
    IPO_CARRY_SAT   = (9  << 7),        // :carry:sat
    IPO_CRND        = (10 << 7),        // :crnd
    IPO_CRND_SAT    = (11 << 7),        // :crnd:sat
    IPO_RND         = (12 << 7),        // :rnd
    IPO_RND_RS1_SAT = (13 << 7),        // :rnd:>>1:sat
    IPO_RND_SAT     = (14 << 7),        // :rnd:sat
    IPO_SAT         = (15 << 7),        // :sat
    IPO_SAT_LS16    = (16 << 7),        // :sat:<<16
    IPO_CHOP        = (17 << 7),        // :chop
    IPO_LIB         = (18 << 7),        // :lib
    IPO_NEG         = (19 << 7),        // :neg
    IPO_POS         = (20 << 7),        // :pos
    IPO_SCALE       = (21 << 7),        // :scale
    IPO_NM          = (22 << 7),        // :nomatch
    IPO_MASK        = (31 << 7),
    IPO_SHIFT       = 7,

    // size modifier (%s)
    SZ_NONE         = (0 << 12),
    SZ_B            = (1 << 12),        // ...b
    SZ_H            = (2 << 12),        // ...h
    SZ_W            = (3 << 12),        // ...w
    SZ_D            = (4 << 12),        // ...d
    SZ_UB           = (5 << 12),        // ...ub
    SZ_UH           = (6 << 12),        // ...uh
    SZ_UW           = (7 << 12),        // ...uw
    SZ_MASK         = (7 << 12),
    SZ_SHIFT        = 12,
    // comparison modifier (%c)
    CMP_EQ          = (0 << 15),        // .eq
    CMP_GT          = (1 << 15),        // .gt
    CMP_GTU         = (2 << 15),        // .gtu
    CMP_GE          = (3 << 15),        // .ge
    CMP_UO          = (4 << 15),        // .uo
    CMP_MASK        = (7 << 15),
    CMP_SHIFT       = 15,
    // conditional jump hint modifier (%t)
    JMP_NONE        = (0 << 12),        // no hint
    JMP_T           = (1 << 12),        // jump is taken
    JMP_NT          = (2 << 12),        // jump is not taken
    JMP_MASK        = (3 << 12),
    JMP_SHIFT       = 12,
    // scatter/gather modifier (%g)
    SG_W            = (0 << 12),        // .w
    SG_H            = (1 << 12),        // .h
    SG_MASK         = (1 << 12),
    SG_SHIFT        = 12,
};

static __inline uint32_t insn_flags( const insn_t &insn, uint32_t subinsn = 0 )
{
    if( subinsn == 0) // also valid for single instructions
        return (insn.segpref << 16) | insn.auxpref_u16[0];
    else
        return (insn.insnpref << 16) | insn.auxpref_u16[1];
}

static __inline uint32_t sub_insn_code( const insn_t &insn, uint32_t subinsn )
{
    if( subinsn == 0)
        return insn.itype & 0xFF;
    else
        return insn.itype >> 8;
}

static __inline uint32_t get_op_index( uint32_t flags )
{
    // returns number of operands used by predicate (i.e. index of 1st actual operand)
    uint32_t pred = flags & PRED_MASK;
    return pred == PRED_NONE? 0 :
           pred == PRED_REG?  1 : 2;
}

/*
  Originally HexagonDepInstrInfo.td contained about 2740 instructions.
  After removing alternative syntax, duplicates, and some simplification,
  we get about 400 instructions below.

  Notes:
  1) for duplex instructions the codes for two sub-instructions are written
     in low and high bytes of insn.itype, and so these must be < 256.
  2) for some instructions the order of arguments is swapped to simplify
     parsing so that Rs=%1 and Rt=%2.
  3) for new_value() to work, always keep %0 as destination.
  4) HVX instructions must be separate.
*/
enum {
    Hex_NONE = 0,
    Hex_abs,                                // %0 = abs(%1)
    Hex_add,                                // %0 = add(%1,%2)
    Hex_add_add,                            // %0 = add(%1,add(%2,%3))
    Hex_add_asl,                            // %0 = add(%1,asl(%0,%2))
    Hex_add_clb,                            // %0 = add(clb(%1),%2)
    Hex_add_lsr,                            // %0 = add(%1,lsr(%0,%2))
    Hex_add_mpyi,                           // %0 = add(%1,mpyi(%2,%3))
    Hex_add_sub,                            // %0 = add(%1,sub(%3,%2))
    Hex_addasl,                             // %0 = addasl(%2,%1,%3)
    Hex_addc,                               // %0 = add(%1,%2,%3)
    Hex_all8,                               // %0 = all8(%1)
    Hex_and,                                // %0 = and(%1,%2)
    Hex_and_and,                            // %0 = and(%1,and(%2,%3))
    Hex_and_asl,                            // %0 = and(%1,asl(%0,%2))
    Hex_and_lsr,                            // %0 = and(%1,lsr(%0,%2))
    Hex_and_or,                             // %0 = and(%1,or(%2,%3))
    Hex_any8,                               // %0 = any8(%1)
    Hex_asl,                                // %0 = asl(%1,%2)
    Hex_aslh,                               // %0 = aslh(%1)
    Hex_asr,                                // %0 = asr(%1,%2)
    Hex_asrh,                               // %0 = asrh(%1)
    Hex_bitsclr,                            // %0 = bitsclr(%1,%2)
    Hex_bitsplit,                           // %0 = bitsplit(%1,%2)
    Hex_bitsset,                            // %0 = bitsset(%1,%2)
    Hex_boundscheck,                        // %0 = boundscheck(%1,%2)
    Hex_brev,                               // %0 = brev(%1)
    Hex_cl0,                                // %0 = cl0(%1)
    Hex_cl1,                                // %0 = cl1(%1)
    Hex_clb,                                // %0 = clb(%1)
    Hex_clip,                               // %0 = clip(%1,%2)
    Hex_clrbit,                             // %0 = clrbit(%1)
    Hex_clrbit2,                            // %0 = clrbit(%1,%2)
    Hex_cmp,                                // %0 = cmp%s%c(%1,%2)
    Hex_combine,                            // %0 = combine(%1,%2)
    Hex_cround,                             // %0 = cround(%1,%2)
    Hex_ct0,                                // %0 = ct0(%1)
    Hex_ct1,                                // %0 = ct1(%1)
    Hex_decbin,                             // %0 = decbin(%1,%2)
    Hex_deinterleave,                       // %0 = deinterleave(%1)
    Hex_extract,                            // %0 = extract(%1,%2)
    Hex_extract3,                           // %0 = extract(%1,%2,%3)
    Hex_extractu,                           // %0 = extractu(%1,%2)
    Hex_extractu3,                          // %0 = extractu(%1,%2,%3)
    Hex_fastcorner9,                        // %0 = fastcorner9(%1,%2)
    Hex_insert,                             // %0 = insert(%1,%2)
    Hex_insert3,                            // %0 = insert(%1,%2,%3)
    Hex_interleave,                         // %0 = interleave(%1)
    Hex_lfs,                                // %0 = lfs(%1,%2)
    Hex_lsl,                                // %0 = lsl(%1,%2)
    Hex_lsr,                                // %0 = lsr(%1,%2)
    Hex_mask,                               // %0 = mask(%1)
    Hex_mask2,                              // %0 = mask(%1,%2)
    Hex_max,                                // %0 = max(%1,%2)
    Hex_maxu,                               // %0 = maxu(%1,%2)
    Hex_memcpy,                             // memcpy(%0,%1,%2)
    Hex_min,                                // %0 = min(%2,%1)
    Hex_minu,                               // %0 = minu(%2,%1)
    Hex_modwrap,                            // %0 = modwrap(%1,%2)
    Hex_mov,                                // %0 = %1
    Hex_mux,                                // %0 = mux(%1,%2,%3)
    Hex_neg,                                // %0 = neg(%1)
    Hex_nop,                                // nop
    Hex_normamt,                            // %0 = normamt(%1)
    Hex_not,                                // %0 = not(%1)
    Hex_or,                                 // %0 = or(%1,%2)
    Hex_or_and,                             // %0 = or(%1,and(%2,%3))
    Hex_or_asl,                             // %0 = or(%1,asl(%0,%2))
    Hex_or_lsr,                             // %0 = or(%1,lsr(%0,%2))
    Hex_or_or,                              // %0 = or(%1,or(%2,%3))
    Hex_packhl,                             // %0 = packhl(%1,%2)
    Hex_parity,                             // %0 = parity(%1,%2)
    Hex_popcount,                           // %0 = popcount(%1)
    Hex_rol,                                // %0 = rol(%1,%2)
    Hex_round,                              // %0 = round(%1)
    Hex_round2,                             // %0 = round(%1,%2)
    Hex_sat,                                // %0 = sat%s(%1)
    Hex_setbit,                             // %0 = setbit(%1)
    Hex_setbit2,                            // %0 = setbit(%1,%2)
    Hex_shuffeb,                            // %0 = shuffeb(%1,%2)
    Hex_shuffeh,                            // %0 = shuffeh(%1,%2)
    Hex_shuffob,                            // %0 = shuffob(%2,%1)
    Hex_shuffoh,                            // %0 = shuffoh(%2,%1)
    Hex_sub,                                // %0 = sub(%2,%1)
    Hex_sub_asl,                            // %0 = sub(%1,asl(%0,%2))
    Hex_sub_lsr,                            // %0 = sub(%1,lsr(%0,%2))
    Hex_subc,                               // %0 = sub(%1,%2,%3)
    Hex_swiz,                               // %0 = swiz(%1)
    Hex_sxtb,                               // %0 = sxtb(%1)
    Hex_sxth,                               // %0 = sxth(%1)
    Hex_sxtw,                               // %0 = sxtw(%1)
    Hex_tableidx,                           // %0 = tableidx%s(%1,%2,%3)
    Hex_togglebit,                          // %0 = togglebit(%1,%2)
    Hex_tstbit,                             // %0 = tstbit(%1,%2)
    Hex_xor,                                // %0 = xor(%1,%2)
    Hex_zxtb,                               // %0 = zxtb(%1)
    Hex_zxth,                               // %0 = zxth(%1)
    // program flow
    Hex_hintjr,                             // hintjr(%0)
    Hex_call,                               // call %0
    Hex_callr,                              // callr %0
    Hex_jump,                               // jump%t %0
    Hex_jumpr,                              // jumpr%t %0
    Hex_cmp_jump,                           // %0 = cmp%c(%1,%2); if (%3) jump%t %4
    Hex_set_jump,                           // %0 = %1; jump %2
    Hex_tstbit_jump,                        // %0 = tstbit(%1,%2); if (%3) jump%t %4
    Hex_loop0,                              // loop0(%0,%1)
    Hex_loop1,                              // loop1(%0,%1)
    Hex_sp1loop0,                           // %0 = sp1loop0(%1,%2)
    Hex_sp2loop0,                           // %0 = sp2loop0(%1,%2)
    Hex_sp3loop0,                           // %0 = sp3loop0(%1,%2)
    Hex_allocframe_raw,                     // allocframe(%0,%1):raw
    Hex_allocframe,                         // allocframe(%0)
    Hex_deallocframe_raw,                   // %0 = deallocframe(%1):raw
    Hex_deallocframe,                       // deallocframe
    Hex_return_raw,                         // %0 = dealloc_return(%1)%t:raw
    Hex_return,                             // dealloc_return%t
    // system/user
    Hex_barrier,                            // barrier
    Hex_brkpt,                              // brkpt
    Hex_dccleana,                           // dccleana(%0)
    Hex_dccleaninva,                        // dccleaninva(%0)
    Hex_dcfetch,                            // dcfetch(%0)
    Hex_dcinva,                             // dcinva(%0)
    Hex_dczeroa,                            // dczeroa(%0)
    Hex_diag,                               // diag(%0)
    Hex_diag0,                              // diag0(%0,%1)
    Hex_diag1,                              // diag1(%0,%1)
    Hex_icinva,                             // icinva(%0)
    Hex_isync,                              // isync
    Hex_l2fetch,                            // l2fetch(%0,%1)
    Hex_pause,                              // pause(%0)
    Hex_syncht,                             // syncht
    Hex_tlbmatch,                           // %0 = tlbmatch(%1,%2)
    Hex_trace,                              // trace(%0)
    Hex_trap0,                              // trap0(%0)
    Hex_trap1,                              // trap1(%0)
    Hex_trap1_2,                            // trap1(%0,%1)
    // system/monitor
    Hex_ciad,                               // ciad(%0)
    Hex_crswap,                             // crswap(%0,%1)
    Hex_cswi,                               // cswi(%0)
    Hex_ctlbw,                              // %0 = ctlbw(%1,%2)
    Hex_dccleanidx,                         // dccleanidx(%0)
    Hex_dccleaninvidx,                      // dccleaninvidx(%0)
    Hex_dcinvidx,                           // dcinvidx(%0)
    Hex_dckill,                             // dckill
    Hex_dctagr,                             // %0 = dctagr(%1)
    Hex_dctagw,                             // dctagw(%0,%1)
    Hex_getimask,                           // %0 = getimask(%1)
    Hex_iassignr,                           // %0 = iassignr(%1)
    Hex_iassignw,                           // iassignw(%0)
    Hex_icdatar,                            // %0 = icdatar(%1)
    Hex_icdataw,                            // icdataw(%0,%1)
    Hex_icinvidx,                           // icinvidx(%0)
    Hex_ickill,                             // ickill
    Hex_ictagr,                             // %0 = ictagr(%1)
    Hex_ictagw,                             // ictagw(%0,%1)
    Hex_k0lock,                             // k0lock
    Hex_k0unlock,                           // k0unlock
    Hex_l2cleanidx,                         // l2cleanidx(%0)
    Hex_l2cleaninvidx,                      // l2cleaninvidx(%0)
    Hex_l2gclean,                           // l2gclean
    Hex_l2gclean1,                          // l2gclean(%0)
    Hex_l2gcleaninv,                        // l2gcleaninv
    Hex_l2gcleaninv1,                       // l2gcleaninv(%0)
    Hex_l2gunlock,                          // l2gunlock
    Hex_l2invidx,                           // l2invidx(%0)
    Hex_l2kill,                             // l2kill
    Hex_l2locka,                            // %0 = l2locka(%1)
    Hex_l2tagr,                             // %0 = l2tagr(%1)
    Hex_l2tagw,                             // l2tagw(%0,%1)
    Hex_l2unlocka,                          // l2unlocka(%0)
    Hex_ldphys,                             // %0 = memw_phys(%1,%2)
    Hex_nmi,                                // nmi(%0)
    Hex_resume,                             // resume(%0)
    Hex_rte,                                // rte
    Hex_setimask,                           // setimask(%0,%1)
    Hex_setprio,                            // setprio(%0,%1)
    Hex_siad,                               // siad(%0)
    Hex_start,                              // start(%0)
    Hex_stop,                               // stop(%0)
    Hex_swi,                                // swi(%0)
    Hex_tlbinvasid,                         // tlbinvasid(%0)
    Hex_tlblock,                            // tlblock
    Hex_tlboc,                              // %0 = tlboc(%1)
    Hex_tlbp,                               // %0 = tlbp(%1)
    Hex_tlbr,                               // %0 = tlbr(%1)
    Hex_tlbunlock,                          // tlbunlock
    Hex_tlbw,                               // tlbw(%0,%1)
    Hex_wait,                               // wait(%0)
    // multiplication
    Hex_cmpy,                               // %0 = cmpy(%1,%2)
    Hex_cmpyi,                              // %0 = cmpyi(%1,%2)
    Hex_cmpyiw,                             // %0 = cmpyiw(%1,%2)
    Hex_cmpyiwh,                            // %0 = cmpyiwh(%1,%2)
    Hex_cmpyr,                              // %0 = cmpyr(%1,%2)
    Hex_cmpyrw,                             // %0 = cmpyrw(%1,%2)
    Hex_cmpyrwh,                            // %0 = cmpyrwh(%1,%2)
    Hex_mpy,                                // %0 = mpy(%1,%2)
    Hex_mpyi,                               // %0 = mpyi(%1,%2)
    Hex_mpysu,                              // %0 = mpysu(%1,%2)
    Hex_mpyu,                               // %0 = mpyu(%1,%2)
    Hex_pmpyw,                              // %0 = pmpyw(%1,%2)
    // floating point
    Hex_conv_d2df,                          // %0 = convert_d2df(%1)
    Hex_conv_d2sf,                          // %0 = convert_d2sf(%1)
    Hex_conv_df2d,                          // %0 = convert_df2d(%1)
    Hex_conv_df2sf,                         // %0 = convert_df2sf(%1)
    Hex_conv_df2ud,                         // %0 = convert_df2ud(%1)
    Hex_conv_df2uw,                         // %0 = convert_df2uw(%1)
    Hex_conv_df2w,                          // %0 = convert_df2w(%1)
    Hex_conv_sf2d,                          // %0 = convert_sf2d(%1)
    Hex_conv_sf2df,                         // %0 = convert_sf2df(%1)
    Hex_conv_sf2ud,                         // %0 = convert_sf2ud(%1)
    Hex_conv_sf2uw,                         // %0 = convert_sf2uw(%1)
    Hex_conv_sf2w,                          // %0 = convert_sf2w(%1)
    Hex_conv_ud2df,                         // %0 = convert_ud2df(%1)
    Hex_conv_ud2sf,                         // %0 = convert_ud2sf(%1)
    Hex_conv_uw2df,                         // %0 = convert_uw2df(%1)
    Hex_conv_uw2sf,                         // %0 = convert_uw2sf(%1)
    Hex_conv_w2df,                          // %0 = convert_w2df(%1)
    Hex_conv_w2sf,                          // %0 = convert_w2sf(%1)
    Hex_dfadd,                              // %0 = dfadd(%1,%2)
    Hex_dfclass,                            // %0 = dfclass(%1,%2)
    Hex_dfcmp,                              // %0 = dfcmp%c(%1,%2)
    Hex_dfmake,                             // %0 = dfmake(%1)
    Hex_dfmax,                              // %0 = dfmax(%1,%2)
    Hex_dfmin,                              // %0 = dfmin(%1,%2)
    Hex_dfmpyfix,                           // %0 = dfmpyfix(%1,%2)
    Hex_dfmpyhh,                            // %0 = dfmpyhh(%1,%2)
    Hex_dfmpylh,                            // %0 = dfmpylh(%1,%2)
    Hex_dfmpyll,                            // %0 = dfmpyll(%1,%2)
    Hex_dfsub,                              // %0 = dfsub(%1,%2)
    Hex_sfadd,                              // %0 = sfadd(%1,%2)
    Hex_sfclass,                            // %0 = sfclass(%1,%2)
    Hex_sfcmp,                              // %0 = sfcmp%c(%1,%2)
    Hex_sffixupd,                           // %0 = sffixupd(%1,%2)
    Hex_sffixupn,                           // %0 = sffixupn(%1,%2)
    Hex_sffixupr,                           // %0 = sffixupr(%1)
    Hex_sfinvsqrta,                         // %0,%1 = sfinvsqrta(%2)
    Hex_sfmake,                             // %0 = sfmake(%1)
    Hex_sfmax,                              // %0 = sfmax(%1,%2)
    Hex_sfmin,                              // %0 = sfmin(%1,%2)
    Hex_sfmpy,                              // %0 = sfmpy(%1,%2)
    Hex_sfmpy3,                             // %0 = sfmpy(%1,%2,%3)
    Hex_sfrecipa,                           // %0,%1 = sfrecipa(%2,%3)
    Hex_sfsub,                              // %0 = sfsub(%1,%2)
    // vector
    Hex_svabsdiff,                          // %0 = vabsdiff%s(%2,%1)
    Hex_svabsh,                             // %0 = vabsh(%1)
    Hex_svabsw,                             // %0 = vabsw(%1)
    Hex_svacsh,                             // %0,%1 = vacsh(%2,%3)
    Hex_svaddh,                             // %0 = vaddh(%1,%2)
    Hex_svaddhub,                           // %0 = vaddhub(%1,%2)
    Hex_svaddub,                            // %0 = vaddub(%1,%2)
    Hex_svadduh,                            // %0 = vadduh(%1,%2)
    Hex_svaddw,                             // %0 = vaddw(%1,%2)
    Hex_svalignb,                           // %0 = valignb(%2,%1,%3)
    Hex_svaslh,                             // %0 = vaslh(%1,%2)
    Hex_svaslw,                             // %0 = vaslw(%1,%2)
    Hex_svasrh,                             // %0 = vasrh(%1,%2)
    Hex_svasrhub,                           // %0 = vasrhub(%1,%2)
    Hex_svasrw,                             // %0 = vasrw(%1,%2)
    Hex_svavg,                              // %0 = vavg%s(%1,%2)
    Hex_svclip,                             // %0 = vclip(%1,%2)
    Hex_svcmp,                              // %0 = vcmp%s%c(%1,%2)
    Hex_svcmpbeq_any,                       // %0 = any8(vcmpb%c(%1,%2))
    Hex_svcmpyi,                            // %0 = vcmpyi(%1,%2)
    Hex_svcmpyr,                            // %0 = vcmpyr(%1,%2)
    Hex_svcnegh,                            // %0 = vcnegh(%1,%2)
    Hex_svconj,                             // %0 = vconj(%1)
    Hex_svcrotate,                          // %0 = vcrotate(%1,%2)
    Hex_svdmpy,                             // %0 = vdmpy(%1,%2)
    Hex_svdmpybsu,                          // %0 = vdmpybsu(%1,%2)
    Hex_svitpack,                           // %0 = vitpack(%1,%2)
    Hex_svlslh,                             // %0 = vlslh(%1,%2)
    Hex_svlslw,                             // %0 = vlslw(%1,%2)
    Hex_svlsrh,                             // %0 = vlsrh(%1,%2)
    Hex_svlsrw,                             // %0 = vlsrw(%1,%2)
    Hex_svmaxb,                             // %0 = vmaxb(%2,%1)
    Hex_svmaxh,                             // %0 = vmaxh(%2,%1)
    Hex_svmaxub,                            // %0 = vmaxub(%2,%1)
    Hex_svmaxuh,                            // %0 = vmaxuh(%2,%1)
    Hex_svmaxuw,                            // %0 = vmaxuw(%2,%1)
    Hex_svmaxw,                             // %0 = vmaxw(%2,%1)
    Hex_svminb,                             // %0 = vminb(%2,%1)
    Hex_svminh,                             // %0 = vminh(%2,%1)
    Hex_svminub,                            // %0 = vminub(%2,%1)
    Hex_svminub2d,                          // %0,%1 = vminub(%3,%2)
    Hex_svminuh,                            // %0 = vminuh(%2,%1)
    Hex_svminuw,                            // %0 = vminuw(%2,%1)
    Hex_svminw,                             // %0 = vminw(%2,%1)
    Hex_svmpybsu,                           // %0 = vmpybsu(%1,%2)
    Hex_svmpybu,                            // %0 = vmpybu(%1,%2)
    Hex_svmpyeh,                            // %0 = vmpyeh(%1,%2)
    Hex_svmpyh,                             // %0 = vmpyh(%1,%2)
    Hex_svmpyhsu,                           // %0 = vmpyhsu(%1,%2)
    Hex_svmpyweh,                           // %0 = vmpyweh(%1,%2)
    Hex_svmpyweuh,                          // %0 = vmpyweuh(%1,%2)
    Hex_svmpywoh,                           // %0 = vmpywoh(%1,%2)
    Hex_svmpywouh,                          // %0 = vmpywouh(%1,%2)
    Hex_svmux,                              // %0 = vmux(%1,%2,%3)
    Hex_svnavg,                             // %0 = vnavg%s(%2,%1)
    Hex_svpmpyh,                            // %0 = vpmpyh(%1,%2)
    Hex_svraddh,                            // %0 = vraddh(%1,%2)
    Hex_svraddub,                           // %0 = vraddub(%1,%2)
    Hex_svradduh,                           // %0 = vradduh(%1,%2)
    Hex_svrcmpyi,                           // %0 = vrcmpyi(%1,%2)
    Hex_svrcmpyr,                           // %0 = vrcmpyr(%1,%2)
    Hex_svrcmpys,                           // %0 = vrcmpys(%1,%2)
    Hex_svrcnegh,                           // %0 = vrcnegh(%1,%2)
    Hex_svrcrotate,                         // %0 = vrcrotate(%1,%2,%3)
    Hex_svrmax,                             // %0 = vrmax%s(%1,%2)
    Hex_svrmin,                             // %0 = vrmin%s(%1,%2)
    Hex_svrmpybsu,                          // %0 = vrmpybsu(%1,%2)
    Hex_svrmpybu,                           // %0 = vrmpybu(%1,%2)
    Hex_svrmpyh,                            // %0 = vrmpyh(%1,%2)
    Hex_svrmpyweh,                          // %0 = vrmpyweh(%1,%2)
    Hex_svrmpywoh,                          // %0 = vrmpywoh(%1,%2)
    Hex_svrndwh,                            // %0 = vrndwh(%1)
    Hex_svrsadub,                           // %0 = vrsadub(%1,%2)
    Hex_svsathb,                            // %0 = vsathb(%1)
    Hex_svsathub,                           // %0 = vsathub(%1)
    Hex_svsatwh,                            // %0 = vsatwh(%1)
    Hex_svsatwuh,                           // %0 = vsatwuh(%1)
    Hex_svsplatb,                           // %0 = vsplatb(%1)
    Hex_svsplath,                           // %0 = vsplath(%1)
    Hex_svspliceb,                          // %0 = vspliceb(%1,%2,%3)
    Hex_svsubh,                             // %0 = vsubh(%2,%1)
    Hex_svsubub,                            // %0 = vsubub(%2,%1)
    Hex_svsubuh,                            // %0 = vsubuh(%2,%1)
    Hex_svsubw,                             // %0 = vsubw(%2,%1)
    Hex_svsxtbh,                            // %0 = vsxtbh(%1)
    Hex_svsxthw,                            // %0 = vsxthw(%1)
    Hex_svtrunehb,                          // %0 = vtrunehb(%1)
    Hex_svtrunehb2,                         // %0 = vtrunehb(%1,%2)
    Hex_svtrunewh,                          // %0 = vtrunewh(%1,%2)
    Hex_svtrunohb,                          // %0 = vtrunohb(%1)
    Hex_svtrunohb2,                         // %0 = vtrunohb(%1,%2)
    Hex_svtrunowh,                          // %0 = vtrunowh(%1,%2)
    Hex_svxaddsubh,                         // %0 = vxaddsubh(%1,%2)
    Hex_svxaddsubw,                         // %0 = vxaddsubw(%1,%2)
    Hex_svxsubaddh,                         // %0 = vxsubaddh(%1,%2)
    Hex_svxsubaddw,                         // %0 = vxsubaddw(%1,%2)
    Hex_svzxtbh,                            // %0 = vzxtbh(%1)
    Hex_svzxthw,                            // %0 = vzxthw(%1)
    // HVX
    Hex_prefixsum,                          // %0 = prefixsum(%1)
    Hex_vabs,                               // %0 = vabs(%1)
    Hex_vabsdiff,                           // %0 = vabsdiff(%1,%2)
    Hex_vadd,                               // %0 = vadd(%1,%2)
    Hex_vadd3,                              // %0 = vadd(%1,%2,%3)
    Hex_vadd2d,                             // %0,%1 = vadd(%2,%3)
    Hex_vaddclb,                            // %0 = vadd(vclb(%1),%2)
    Hex_valign,                             // %0 = valign(%1,%2,%3)
    Hex_vand,                               // %0 = vand(%1,%2)
    Hex_vasl,                               // %0 = vasl(%1,%2)
    Hex_vasr,                               // %0 = vasr(%1,%2)
    Hex_vasr3,                              // %0 = vasr(%1,%2,%3)
    Hex_vasrinto,                           // %0 = vasrinto(%1,%2)
    Hex_vavg,                               // %0 = vavg(%1,%2)
    Hex_vcombine,                           // %0 = vcombine(%1,%2)
    Hex_vcl0,                               // %0 = vcl0(%1)
    Hex_vcmp,                               // %0 = vcmp%c(%1,%2)
    Hex_vdeal,                              // %0 = vdeal(%1)
    Hex_vdeal3,                             // vdeal(%0,%1,%2)
    Hex_vdeal4,                             // %0 = vdeal(%1,%2,%3)
    Hex_vdeale,                             // %0 = vdeale(%1,%2)
    Hex_vdelta,                             // %0 = vdelta(%1,%2)
    Hex_vdmpy,                              // %0 = vdmpy(%1,%2)
    Hex_vdmpy3,                             // %0 = vdmpy(%1,%2,%3)
    Hex_vdsad,                              // %0 = vdsad(%1,%2)
    Hex_vextract,                           // %0 = vextract(%1,%2)
    Hex_vgather,                            // %0 = vgather(%1,%2,%3)%g
    Hex_vhist,                              // vhist
    Hex_vhist1,                             // vhist(%0)
    Hex_vinsert,                            // %0 = vinsert(%1)
    Hex_vlalign,                            // %0 = vlalign(%1,%2,%3)
    Hex_vlsr,                               // %0 = vlsr(%1,%2)
    Hex_vlut16,                             // %0 = vlut16(%1,%2,%3)
    Hex_vlut32,                             // %0 = vlut32(%1,%2,%3)
    Hex_vlut4,                              // %0 = vlut4(%1,%2)
    Hex_vmax,                               // %0 = vmax(%1,%2)
    Hex_vmin,                               // %0 = vmin(%1,%2)
    Hex_vmpa,                               // %0 = vmpa(%1,%2)
    Hex_vmpa3,                              // %0 = vmpa(%0,%1,%2)
    Hex_vmps,                               // %0 = vmps(%0,%1,%2)
    Hex_vmpy,                               // %0 = vmpy(%1,%2)
    Hex_vmpye,                              // %0 = vmpye(%1,%2)
    Hex_vmpyi,                              // %0 = vmpyi(%1,%2)
    Hex_vmpyie,                             // %0 = vmpyie(%1,%2)
    Hex_vmpyieo,                            // %0 = vmpyieo(%1,%2)
    Hex_vmpyio,                             // %0 = vmpyio(%1,%2)
    Hex_vmpyo,                              // %0 = vmpyo(%1,%2)
    Hex_vmux,                               // %0 = vmux(%1,%2,%3)
    Hex_vnavg,                              // %0 = vnavg(%1,%2)
    Hex_vnormamt,                           // %0 = vnormamt(%1)
    Hex_vnot,                               // %0 = vnot(%1)
    Hex_vor,                                // %0 = vor(%1,%2)
    Hex_vpack,                              // %0 = vpack(%1,%2)
    Hex_vpacke,                             // %0 = vpacke(%1,%2)
    Hex_vpacko,                             // %0 = vpacko(%1,%2)
    Hex_vpopcount,                          // %0 = vpopcount(%1)
    Hex_vrdelta,                            // %0 = vrdelta(%1,%2)
    Hex_vrmpy,                              // %0 = vrmpy(%1,%2)
    Hex_vrmpy3,                             // %0 = vrmpy(%1,%2,%3)
    Hex_vror,                               // %0 = vror(%1,%2)
    Hex_vrotr,                              // %0 = vrotr(%1,%2)
    Hex_vround,                             // %0 = vround(%1,%2)
    Hex_vrsad,                              // %0 = vrsad(%1,%2,%3)
    Hex_vsat,                               // %0 = vsat(%1,%2)
    Hex_vsatdw,                             // %0 = vsatdw(%1,%2)
    Hex_vscatter,                           // vscatter(%0,%1,%2)%g = %3
    Hex_vscatterrls,                        // %0:scatter_release
    Hex_vsetq,                              // %0 = vsetq(%1)
    Hex_vsetq2,                             // %0 = vsetq2(%1)
    Hex_vshuff,                             // %0 = vshuff(%1)
    Hex_vshuff3,                            // vshuff(%0,%1,%2)
    Hex_vshuff4,                            // %0 = vshuff(%1,%2,%3)
    Hex_vshuffe,                            // %0 = vshuffe(%1,%2)
    Hex_vshuffo,                            // %0 = vshuffo(%1,%2)
    Hex_vshuffoe,                           // %0 = vshuffoe(%1,%2)
    Hex_vsplat,                             // %0 = vsplat(%1)
    Hex_vsub,                               // %0 = vsub(%1,%2)
    Hex_vsub3,                              // %0 = vsub(%1,%2,%3)
    Hex_vsub2d,                             // %0,%1 = vsub(%2,%3)
    Hex_vswap,                              // %0 = vswap(%1,%2,%3)
    Hex_vsxt,                               // %0 = vsxt(%1)
    Hex_vtmpy,                              // %0 = vtmpy(%1,%2)
    Hex_vunpack,                            // %0 = vunpack(%1)
    Hex_vunpacko,                           // %0 = vunpacko(%1)
    Hex_vwhist128,                          // vwhist128
    Hex_vwhist128_1,                        // vwhist128(%0)
    Hex_vwhist128_2,                        // vwhist128(%0,%1)
    Hex_vwhist256,                          // vwhist256
    Hex_vwhist256_1,                        // vwhist256(%0)
    Hex_vxor,                               // %0 = vxor(%1,%2)
    Hex_vzxt,                               // %0 = vzxt(%1)
    // HVX V66 AI extension
    Hex_vr16mpyz,                           // %0 = vr16mpyz(%1,%2)
    Hex_vr16mpyzs,                          // %0 = vr16mpyzs(%1,%2)
    Hex_vr8mpyz,                            // %0 = vr8mpyz(%1,%2)
    Hex_vrmpyz,                             // %0 = vrmpyz(%1,%2)
    Hex_zextract,                           // %0 = zextract(%1)
    Hex_NUM_INSN,
};
