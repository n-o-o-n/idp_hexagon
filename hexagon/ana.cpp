/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "common.h"

#define EXTEND(val, align)          (extender? uint32_t(extender) | ((val) & 0x3F) : ((val) << (align)))
#define MUST_EXTEND(val)            (uint32_t(extender) | (val))
#define LOW(range)                  (0? range)
#define HIGH(range)                 (1? range)
#define MASK(bits)                  ((1 << (bits)) - 1)
#define BITS(range)                 ((word >> LOW(range)) & MASK(HIGH(range) - LOW(range) + 1))
#define SBITS(range)                ((int32_t)(word << (31 - HIGH(range))) >> (31 - HIGH(range) + LOW(range)))
#define BIT(bit)                    ((word >> (bit)) & 1)
#define SBIT(bit)                   ((int32_t)(word << (31 - (bit))) >> 31)
#define SWAP(a, b)                  do { auto _tmp = (a); (a) = (b); (b) = _tmp; } while(0)

#define DD                          (REG_DOUBLE << 0)
#define SS                          (REG_DOUBLE << 10)
#define TT                          (REG_DOUBLE << 20)
#define RP(df, uf, vf)              (REG_POST_##df | (REG_POST_##uf << 10) | (REG_POST_##vf << 20))
#define FLG_D(f)                    ((f) & 0x3FF)
#define FLG_S(f)                    (((f) >> 10) & 0x3FF)
#define FLG_T(f)                    (((f) >> 20) & 0x3FF)
#define REG_POST__                  0

//
// packet parsing
//

#define PARSE(w)                    (((w) >> 14) & 3)
enum {
    PARSE_DUPLEX    = 0b00,     // duplex and end of packet
    PARSE_LOOP_END  = 0b10,     // packet is last in HW loop
    PARSE_LAST      = 0b11,     // end of packet
};

// start of current instruction packet (PC value)
static ea_t s_pkt_start;
// current instruction address
static ea_t s_insn_ea;

ea_t find_packet_end( ea_t ea )
{
    // returns address of the start of next packet
    // align on dwords
    ea &= ~2;
    // scan instructions forward in order to find the packet end
    // packet can have max 4 dwords including the current one, and we don't check the last dword
    for( ea_t end = ea + 8; ea <= end; ea += 4 )
    {
        uint32_t parse = PARSE(get_dword( ea ));
        if( parse == PARSE_LAST || parse == PARSE_DUPLEX )
            break;
    }
    return ea + 4;
}

static bool find_packet_boundaries( ea_t ea, ea_t *pkt_start, ea_t *pkt_end )
{
    // returns starting addresses of this and of the next packets
    // WARNING: the result may be wrong in case of mixed instructions and data
    auto seg = getseg( ea );
    if( !seg ) return false;
    // align on dwords
    ea &= ~2;
    ea_t start = seg->start_ea, end = find_packet_end( ea );
    *pkt_end = end;
    // packets contain max 4 dwords
    if( end > start + 16 ) start = end - 16;
    // scan instructions backwards in order to find the packet start
    while( ea > start )
    {
        ea -= 4;
        // end of packet?
        uint32_t parse = PARSE(get_dword( ea ));
        if( parse == PARSE_LAST || parse == PARSE_DUPLEX )
        {
            *pkt_start = ea + 4;
            return true;
        }
    }
    *pkt_start = ea;
    return true;
}

static uint32_t get_endloop( ea_t pkt_ea )
{
    uint32_t flags = 0;
    // check 1st word
    uint32_t parse = PARSE(get_dword( pkt_ea ));
    if( parse == PARSE_LOOP_END )
        flags |= INSN_ENDLOOP0;
    else if( parse == PARSE_LAST || parse == PARSE_DUPLEX )
        return 0;
    // check 2nd word
    parse = PARSE(get_dword( pkt_ea + 4 ));
    if( parse == PARSE_LOOP_END )
        flags |= INSN_ENDLOOP1;
    return flags;
}

static bool is_hvx( const insn_t &insn )
{
    // return true if this is a HVX instruction
    if( (insn.flags & INSN_DUPLEX) )
        return false;
    if( Hex_HVX_FIRST <= insn.itype && insn.itype <= Hex_HVX_LAST )
        return true;
    if( insn.ops[0].type == o_reg && IN_RANGE(insn.ops[0].reg, REG_V0, REG_VTMP) ||
        insn.ops[1].type == o_reg && IN_RANGE(insn.ops[1].reg, REG_V0, REG_VTMP) )
        return true;
    return false;
}

static uint32_t new_value( uint32_t nt, bool hvx = false )
{
    if( nt >= 8 || (nt & 6) == 0 ) return ~0u;
    // we're going to parse other instructions, so save globals
    ea_t saved_pkt_start = s_pkt_start, saved_ea = s_insn_ea, ea = s_insn_ea;
    uint32_t offset = (nt & 6) >> 1, result = ~0u;
    insn_t temp;

    // scan instructions up until the start of packet
    while( 1 )
    {
        ea = prev_not_tail( ea );
        if( hvx || offset == 1 )
        {
            // avoid calling decode_insn()
            memset( &temp, 0, sizeof(temp) );
            temp.ea = ea;
            if( !ana( temp ) ) goto __cleanup;
            // skip scalars when calculating distances for vectors
            if( hvx && !is_hvx( temp ) ) ++offset;
        }
        if( --offset == 0 ) break;
        // couldn't find producer?
        if( ea <= saved_pkt_start ) goto __cleanup;
    }
    // we got the producer, find out the operand
    // TODO: check if duplexes have to be supported
    {
        const op_t *op = temp.ops;
        assert( op->type == o_reg );
        if( !hvx )
        {
            assert( (nt & 1) == 0 );
            result = op->reg;
        }
        else // hvx
        {
            // a pair of vector registers?
            if( IN_RANGE(op->reg, REG_V0, REG_V0 + 31) && (op->specval & REG_DOUBLE) )
                result = op->reg ^ (nt & 1);
            else
                // some instructions produce 2 output registers
                result = op[(nt & 1)].reg;
        }
    }
__cleanup:
    // restore globals
    s_pkt_start = saved_pkt_start, s_insn_ea = saved_ea;
    return result;
}

//
// helper functions for different kinds of operands
//

static void op_reg( op_t &op, uint32_t reg, uint32_t flags = 0 )
{
    // a register operand
    op.type = o_reg;
    op.reg = reg;
    op.specval = flags; // REG_XXX, REG_PRE_XXX, REG_POST_XXX
    op.dtype = dt_dword;
}

static void op_reg_off( op_t &op, uint32_t reg, uint32_t imm )
{
    // Rs + #u14 (used only in dcfetch instruction)
    op.type = o_reg_off;
    op.reg = reg;
    op.value = imm;
    op.dtype = dt_dword;
}

static void op_imm_ex( op_t &op, uint32_t imm, uint32_t flags )
{
    op.type = o_imm;
    op.value = imm;
    op.dtype = dt_dword;
    op.specflag1 = flags; // IMM_XXX
}

static __inline void op_imm( op_t &op, uint32_t imm, bool _signed = false, bool extended = false )
{
    op_imm_ex( op, imm, (_signed? IMM_SIGNED : 0) | (extended? IMM_EXTENDED : 0) );
}

static __inline uint32_t mem_shift( uint32_t type )
{
    // returns offset shift for specified memory type
    static const uint8_t shifts[16] = { 0,0,0,0,1,1,2,3,7,7,0,0 };
    return shifts[ type & MEM_TYPE_MASK ];
}

static __inline uint32_t mem_dtype( uint32_t type )
{
    // convert MEM_XX into op_dtype_t
    type &= MEM_TYPE_MASK;
    return type == MEM_V || type == MEM_VU ? dt_byte64 : // in fact it's 128 bytes
           type == MEM_H || type == MEM_UH? dt_word :
           type == MEM_W? dt_dword :
           type == MEM_D? dt_qword :
           dt_byte;
}

static void op_mem_ind( op_t &op, uint32_t type, uint32_t reg, uint32_t imm, bool extended = false )
{
    // memXX(Rs + #s11) or memXX(gp + #u16)
    op.type = o_displ;
    op.specval = type | (extended? MEM_IMM_EXT : 0);
    op.dtype = mem_dtype( type );
    op.reg = reg;
    op.addr = imm;
}

static void op_mem_abs( op_t &op, uint32_t type, uint32_t abs )
{
    // memXX(##u32)
    op.type = o_mem;
    op.specval = type;
    op.dtype = mem_dtype( type );
    op.value = abs;
}

static void op_mem_abs_set( op_t &op, uint32_t type, uint32_t re, uint32_t abs )
{
    // memXX(Re=##u32)
    op.type = o_mem_abs_set;
    op.specval = type;
    op.dtype = mem_dtype( type );
    op.reg = re;
    op.value = abs;
}

static void op_mem_abs_off( op_t &op, uint32_t type, uint32_t ru, uint32_t u2, uint32_t abs )
{
    // memXX(Ru << #u2 + ##u32)
    op.type = o_mem_abs_off;
    op.specval = type;
    op.dtype = mem_dtype( type );
    op.reg = ru;
    op.specflag2 = u2;
    op.value = abs;
}

static void op_mem_locked( op_t &op, uint32_t type, uint32_t rs, uint32_t pd = 0 )
{
    // memXX_locked(Rs[,Pd])
    op.type = o_mem_locked;
    op.specval = type | MEM_LOCKED;
    op.dtype = mem_dtype( type );
    op.reg = rs;
    op.specflag2 = pd;
}

static void op_mem_ind_off( op_t &op, uint32_t type, uint32_t rs, uint32_t ru, uint32_t imm )
{
    // memXX(Rs + Ru << #u2)
    assert( rs < 256 && ru < 256 && imm < 4 );
    op.type = o_mem_ind_off;
    op.specval = type;
    op.dtype = mem_dtype( type );
    op.reg = (rs << 8) | ru;
    op.value = imm;
}

static void op_mem_inc( op_t &op, uint32_t otype, uint32_t type, uint32_t rx, int32_t inc, uint32_t mu = 0 )
{
    // memXX(Rx++...)
    op.type = otype; // o_mem_inc_xxx or o_mem_circ_xxx
    op.specval = type;
    op.dtype = mem_dtype( type );
    op.reg = rx;
    op.value = inc;
    op.specflag2 = mu;
}

static void op_mxmem( op_t &op, uint32_t type, uint32_t rs, uint32_t rt = 0xFF )
{
    // mxmem[2](Rs[,Rt])
    op.type = o_mxmem;
    op.specval = type;
    op.dtype = dt_byte; // doesn't matter
    op.reg = (rs << 8) | rt;
}

static void op_acc( op_t &op, uint32_t type = 0, uint32_t rs = 0xFF )
{
    // acc[(Rs)][:...]
    op.type = o_acc;
    op.specval = type;
    op.dtype = dt_byte; // doesn't matter
    op.reg = rs;
}

static void op_pcrel( op_t &op, int32_t offset )
{
    // a PC-relative offset
    // note: PC points to the start of this instruction packet
    op.type = o_near;
    op.addr = s_pkt_start + offset;
    op.dtype = dt_code;
}

static __inline uint8_t gen_sub_reg( uint32_t v )
{
    // r0..r7, r16..r23
    assert( v < 16 );
    return REG_R( v + (v < 8? 0 : 8) );
};

//
// core instructions parsing
//

static uint32_t iclass_1_CJ( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    if( BIT(0) != 0 ) return 0;
    uint32_t rs = gen_sub_reg( BITS(19:16) ), rt = gen_sub_reg( BITS(11:8) );
    int32_t off = EXTEND( (SBITS(21:20) << 7) | BITS(7:1), 2 );

    if( BITS(27:26) == 0 && BITS(24:23) != 0b11 )
    {
        // pu = cmp%c(Rs16,#II); if ([!]pu.new) jump%t Ii
        uint32_t pu = REG_P( BIT(25) );
        op_reg( ops[0], pu );
        op_reg( ops[1], rs );
        op_imm( ops[2], BITS(12:8) );
        op_reg( ops[3], pu, (BIT(22)? REG_PRE_NOT : 0) | REG_POST_NEW );
        op_pcrel( ops[4], off );
        flags = (BITS(24:23) << 15) | // CMP_EQ/GT/GTU
                (BIT(13)? JMP_T : JMP_NT);
        return Hex_cmp_jump;
    }
    if( BITS(27:26) == 0 && BITS(24:23) == 0b11 && BITS(12:10) == 0 )
    {
        // pu = cmp%c(Rs16,#{0|-1}); if ([!]pu.new) jump%t Ii
        uint32_t pu = REG_P( BIT(25) );
        op_reg( ops[0], pu );
        op_reg( ops[1], rs );
        if( BIT(9) ) op_imm( ops[2], 0 );
        else         op_imm( ops[2], -1, true );
        op_reg( ops[3], pu, (BIT(22)? REG_PRE_NOT : 0) | REG_POST_NEW );
        op_pcrel( ops[4], off );
        flags = (BIT(8) << 15) | // CMP_EQ | CMP_GT
                (BIT(13)? JMP_T : JMP_NT);
        return BIT(9)? Hex_tstbit_jump : Hex_cmp_jump;
    }
    if( BITS(27:25) == 0b010 && BITS(24:23) != 0b11 )
    {
        // pu = cmp%c(Rs16,Rt16); if ([!]pu.new) jump%t Ii
        uint32_t pu = REG_P( BIT(12) );
        op_reg( ops[0], pu );
        op_reg( ops[1], rs );
        op_reg( ops[2], rt );
        op_reg( ops[3], pu, (BIT(22)? REG_PRE_NOT : 0) | REG_POST_NEW );
        op_pcrel( ops[4], off );
        flags = (BITS(24:23) << 15) | // CMP_EQ/GT/GTU
                (BIT(13)? JMP_T : JMP_NT);
        return Hex_cmp_jump;
    }
    if( BITS(27:22) == 0b011000 )
    {
        // Rd16 = #II; jump Ii
        op_reg( ops[0], rs );
        op_imm( ops[1], BITS(13:8) );
        op_pcrel( ops[2], off );
        return Hex_set_jump;
    }
    if( BITS(27:22) == 0b011100 && BITS(13:12) == 0 )
    {
        // Rd16 = Rs16; jump Ii
        op_reg( ops[0], rt );
        op_reg( ops[1], rs );
        op_pcrel( ops[2], off );
        return Hex_set_jump;
    }
    return 0;
}

static uint32_t iclass_2_NCJ( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    // if ([!]cond(Ns8.new...)) jump%t Ii
    if( BIT(19) != 0 || BIT(0) != 0 ) return 0;
    static const uint8_t cond_flg[16] = {
        PRED_EQ,  PRED_GT, PRED_GTU, PRED_GT,
        PRED_GTU, 0,       0,        0,
        PRED_EQ,  PRED_GT, PRED_GTU, PRED_BS0,
        PRED_EQ,  PRED_GT, 0, 0,
    };
    uint32_t cond = BITS(27:23), ns = BITS(18:16), rt = BITS(12:8);
    uint32_t target = EXTEND( (SBITS(21:20) << 7) | BITS(7:1), 2 );

    switch( cond )
    {
    case 0: case 1: case 2:
        op_reg( ops[PRED_A], new_value( ns ), REG_POST_NEW );
        op_reg( ops[PRED_B], REG_R(rt) );
        break;
    case 3: case 4: // swapped arguments
        op_reg( ops[PRED_A], REG_R(rt) );
        op_reg( ops[PRED_B], new_value( ns ), REG_POST_NEW );
        break;
    case 8: case 9: case 10:
        op_reg( ops[PRED_A], new_value( ns ), REG_POST_NEW );
        op_imm( ops[PRED_B], rt );
        break;
    case 11: case 12: case 13:
        if( rt ) return 0;
        op_reg( ops[PRED_A], new_value( ns ), REG_POST_NEW );
        if( cond == 11 ) op_imm( ops[PRED_B], 0 );
        else             op_imm( ops[PRED_B], -1, true );
        break;
    default:
        return 0;
    }
    op_pcrel( ops[0], target );
    flags = (cond_flg[cond] + (BIT(22)? PRED_NOT : 0)) |
            (BIT(13)? JMP_T : JMP_NT);
    return Hex_jump;
}

static const uint8_t types_ld[8] = { MEM_B, MEM_UB, MEM_H, MEM_UH, MEM_W, 255, MEM_D, 255 };
static const uint8_t types_st[8] = { MEM_B, 255, MEM_H, MEM_H, MEM_W, 255, MEM_D, 255 };
static const uint8_t types_nv[4] = { MEM_B, MEM_H, MEM_W, 255 };

static uint32_t iclass_3_V4LDST( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t rs = REG_R( BITS(20:16) ), ru = REG_R( BITS(12:8) );
    uint32_t pv = REG_P( BITS(6:5) ),   rt = REG_R( BITS(4:0) );
    bool extended = extender != 0;

    if( BITS(27:26) == 0b00 )
    {
        // if ([!}Pv4[.new]) Rd32 = memXX(Rs32+Rt32<<#Ii)
        uint32_t type = types_ld[ BITS(23:21) ];
        if( type == 255 ) return 0;

        flags = PRED_REG;
        op_reg( ops[PRED_A], pv, (BIT(24)? REG_PRE_NOT : 0) |
                                 (BIT(25)? REG_POST_NEW : 0) );
        op_reg( ops[0], rt, type == MEM_D? REG_DOUBLE : 0 );
        op_mem_ind_off( ops[1], type, rs, ru, (BIT(13) << 1) | BIT(7) );
        return Hex_mov;
    }
    else if( BITS(27:26) == 0b01 )
    {
        // if ([!]Pv4[.new]) memX(Rs32+Ru32<<#Ii) = Rt32[.h|.new]
        uint32_t code = BITS(23:21);
        uint32_t type = (code != 5)? types_st[ code ] : types_nv[ BITS(4:3) ];
        if( type == 255 ) return 0;

        flags = PRED_REG;
        op_reg( ops[PRED_A], pv, (BIT(24)? REG_PRE_NOT : 0) |
                                 (BIT(25)? REG_POST_NEW : 0) );
        op_mem_ind_off( ops[0], type, rs, ru, (BIT(13) << 1) | BIT(7) );
        op_reg( ops[1], code == 5? new_value( BITS(2:0) ) : rt,
                        code == 5? REG_POST_NEW :
                        code == 3? REG_POST_HI :
                        code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    else if( BITS(27:25) == 0b100 )
    {
        // if ([!]Pv4[.new]) memX(Rs32+#Ii) = #II
        uint32_t size = BITS(22:21), type = types_nv[ size ];
        if( type == 255 ) return 0;

        flags = PRED_REG;
        op_reg( ops[PRED_A], pv, (BIT(23)? REG_PRE_NOT : 0) |
                                 (BIT(24)? REG_POST_NEW : 0) );
        op_mem_ind( ops[0], type, rs, BITS(12:7) << size );
        op_imm( ops[1], EXTEND( (SBIT(13) << 5) | BITS(4:0), 0 ), true, extended );
        return Hex_mov;
    }
    else if( BITS(27:24) == 0b1010 && BITS(6:5) == 0 )
    {
        // Rd32 = memXX(Rs32+Rt32<<#Ii)
        uint32_t type = types_ld[ BITS(23:21) ];
        if( type == 255 ) return 0;

        op_reg( ops[0], rt, type == MEM_D? REG_DOUBLE : 0 );
        op_mem_ind_off( ops[1], type, rs, ru, (BIT(13) << 1) | BIT(7) );
        return Hex_mov;
    }
    else if( BITS(27:24) == 0b1011 && BITS(6:5) == 0 )
    {
        // memX(Rs32+Ru32<<#Ii) = Rt32[.h|.new]
        uint32_t code = BITS(23:21);
        uint32_t type = (code != 5)? types_st[ code ] : types_nv[ BITS(4:3) ];
        if( type == 255 ) return 0;

        op_mem_ind_off( ops[0], type, rs, ru, (BIT(13) << 1) | BIT(7) );
        op_reg( ops[1], code == 5? new_value( BITS(2:0) ) : rt,
                        code == 5? REG_POST_NEW :
                        code == 3? REG_POST_HI :
                        code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    else if( BITS(27:23) == 0b11000 )
    {
        // memX(Rs32+#Ii) = #II
        uint32_t size = BITS(22:21), type = types_nv[ size ];
        if( type == 255 ) return 0;

        op_mem_ind( ops[0], type, rs, BITS(12:7) << size );
        op_imm( ops[1], EXTEND( (SBIT(13) << 7) | BITS(6:0), 0 ), true, extended );
        return Hex_mov;
    }
    else if( BITS(27:25) == 0b111 && BIT(23) == 0 && BIT(13) == 0 )
    {
        // memX(Rs32+#Ii) *= {Rt32|#II|clrbit(#II)|setbit(#II)}
        static const uint8_t memop[4] = { IAT_ADD, IAT_SUB, IAT_AND, IAT_OR };
        uint32_t size = BITS(22:21), type = types_nv[ size ];
        if( type == 255 ) return 0;

        op_mem_ind( ops[0], type, rs, EXTEND( BITS(12:7), size ), extended );
        if( BIT(24) ) op_imm( ops[1], BITS(4:0) );
        else          op_reg( ops[1], rt );
        if( (BIT(24) & BIT(6)) )
            return BIT(5)? Hex_setbit : Hex_clrbit;
        flags = memop[ BITS(6:5) ];
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_4_V2LDST( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);
    uint32_t code = BITS(23:21), code_nv = BITS(12:11);
    bool extended = extender != 0;

    if( BIT(27) == 0 && BIT(24) == 0 && BIT(2) == 0 )
    {
        // if ([!]Pv4[.new]) memX(Rs32+#Ii) = Rt32[.h|.new]
        uint32_t type = code != 5? types_st[ code ] : types_nv[ code_nv ];
        if( type == 255 ) return 0;
        uint32_t off = EXTEND( (BIT(13) << 5) | BITS(7:3), mem_shift( type ) );

        op_reg( ops[PRED_A], REG_P(BITS(1:0)),
                (BIT(25)? REG_POST_NEW : 0) |
                (BIT(26)? REG_PRE_NOT : 0) );
        op_mem_ind( ops[0], type, REG_R(s5), off, extended );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                        code == 5? REG_POST_NEW :
                        code == 3? REG_POST_HI :
                        code == 6? REG_DOUBLE : 0 );
        flags = PRED_REG;
        return Hex_mov;
    }
    if( BIT(27) == 0 && BIT(24) == 1 && BIT(13) == 0 )
    {
        // if ([!]Pt4[.new]) Rd32 = memXX(Rs32+#Ii)
        uint32_t type = types_ld[ code ];
        if( type == 255 ) return 0;
        uint32_t off = EXTEND( BITS(10:5), mem_shift( type ) );

        op_reg( ops[PRED_A], REG_P(BITS(12:11)),
                (BIT(25)? REG_POST_NEW : 0) |
                (BIT(26)? REG_PRE_NOT : 0) );
        op_reg( ops[0], REG_R(d5), (type == MEM_D? REG_DOUBLE : 0) );
        op_mem_ind( ops[1], type, REG_R(s5), off, extended );
        flags = PRED_REG;
        return Hex_mov;
    }

    if( BIT(27) == 1 && BIT(24) == 0 )
    {
        // memX([gp+]#Ii) = Rt32[.h|.new]
        uint32_t type = code != 5? types_st[ code ] : types_nv[ code_nv ];
        if( type == 255 ) return 0;
        uint32_t off = EXTEND( (BITS(26:25) << 14) | (BITS(20:16) << 9) | (BIT(13) << 8) | BITS(7:0), mem_shift( type ) );

        if( extender ) op_mem_abs( ops[0], type, off );
        else           op_mem_ind( ops[0], type, REG_GP, off );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                 code == 5? REG_POST_NEW :
                 code == 3? REG_POST_HI :
                 code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    if( BIT(27) == 1 && BIT(24) == 1 )
    {
        // Rd[d]32 = memXX([gp+]#Ii)
        uint32_t type = types_ld[ code ];
        if( type == 255 ) return 0;
        uint32_t off = EXTEND( (BITS(26:25) << 14) | (BITS(20:16) << 9) | BITS(13:5), mem_shift( type ) );

        op_reg( ops[0], REG_R(d5), (type == MEM_D? REG_DOUBLE : 0) );
        if( extender ) op_mem_abs( ops[1], type, off );
        else           op_mem_ind( ops[1], type, REG_GP, off );
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_5_J( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t code1 = BITS(27:25), code2 = BITS(24:21);
    uint32_t rs32 = REG_R( BITS(20:16) ), pu4 = REG_P( BITS(9:8) );
    int32_t  off;

    switch( code1 )
    {
    case 0b000:
        if( BITS(7:0) != 0 )
            break;

        if( code2 == 0b0101 && BITS(13:8) == 0 )
        {
            // callr Rs32
            op_reg( ops[0], rs32 );
            return Hex_callr;
        }
        else if( code2 == 0b0110 && BITS(13:8) == 0 )
        {
            // callrh Rs32
            op_reg( ops[0], rs32 );
            return Hex_callrh;
        }
        else if( BITS(24:22) == 0b100 && BITS(13:10) == 0 )
        {
            // if ([!]Pu4) callr Rs32
            op_reg( ops[PRED_A], pu4, BIT(21)? REG_PRE_NOT : 0 );
            op_reg( ops[0], rs32 );
            flags = PRED_REG;
            return Hex_callr;
        }
        break;

    case 0b001:
        if( BITS(7:0) != 0 )
            break;

        if( BITS(24:22) == 0b010 && BITS(13:8) == 0 )
        {
            // {jumpr|hintjr}(Rs32)
            op_reg( ops[0], rs32 );
            return BIT(21)? Hex_hintjr : Hex_jumpr;
        }
        else if( code2 == 0b0110 && BITS(13:8) == 0 )
        {
            // jumprh Rs32
            op_reg( ops[0], rs32 );
            return Hex_jumprh;
        }
        else if( BITS(24:22) == 0b101 && BIT(13) == 0 && BIT(10) == 0 )
        {
            // if ([!]Pu4[.new]) jumpr%t Rs32
            op_reg( ops[PRED_A], pu4, (BIT(21)? REG_PRE_NOT : 0) |
                                      (BIT(11)? REG_POST_NEW : 0) );
            op_reg( ops[0], rs32 );
            flags = PRED_REG;
            if( BIT(11) ) // only for pu.new
                flags |= BIT(12)? JMP_T : JMP_NT;
            return Hex_jumpr;
        }
        break;

    case 0b100: case 0b101:
        // jump/call Ii
        if( BIT(0) != 0 ) break;
        off = EXTEND( (SBITS(24:16) << 13) | BITS(13:1), 2 );
        op_pcrel( ops[0], off );
        return code1 == 4? Hex_jump : Hex_call;

    case 0b110:
        // if ([!]Pu4[.new]) jump%t/call Ii
        if( BIT(0) != 0 || BIT(10) != 0 ) break;
        if( BIT(24) && BITS(12:11) != 0 ) break;
        off = EXTEND( (SBITS(23:22) << 13) | (BITS(20:16) << 8) | (BIT(13) << 7) | BITS(7:1), 2 );
        op_reg( ops[PRED_A], pu4, (BIT(21)? REG_PRE_NOT : 0) |
                                  (BIT(11)? REG_POST_NEW : 0) );
        op_pcrel( ops[0], off );
        flags = PRED_REG;
        if( !BIT(24) && BIT(11) ) // only for pu.new
            flags |= BIT(12)? JMP_T : JMP_NT;
        return BIT(24)? Hex_call : Hex_jump;
    }
    return 0;
}

static uint32_t iclass_6_CR( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t s2 = BITS(17:16), t2 = BITS(9:8), u2 = BITS(7:6), d2 = BITS(1:0);
    uint32_t s5 = BITS(20:16), d5 = BITS(4:0);
    bool extended = extender != 0;
    static const uint8_t loops[8] = {
        Hex_loop0, Hex_loop1, 0, 0,
        0, Hex_sp1loop0, Hex_sp2loop0, Hex_sp3loop0,
    };

    if( BITS(27:24) == 0b0000 && BIT(13) == 0 && BITS(7:5) == 0 && BITS(2:0) == 0 )
    {
        // p3 = sp{1-3}loop0(Ii,Rs32) or loop{0|1}(Ii,Rs32)
        uint32_t type = loops[ BITS(23:21) ], rp = 0;
        if( !type ) return 0;
        if( type >= Hex_sp1loop0 )
            op_reg( ops[rp++], REG_P(3) );
        op_pcrel( ops[rp], EXTEND( (SBITS(12:8) << 2) | BITS(4:3), 2 ) );
        op_reg( ops[rp+1], REG_R(s5) );
        return type;
    }
    if( BITS(27:24) == 0b0001 && BIT(0) == 0 )
    {
        // if (Rs32*=#0) jump%t Ii
        op_reg( ops[PRED_A], REG_R(s5) );
        op_imm( ops[PRED_B], 0 );
        op_pcrel( ops[0], (SBIT(21) << 14) | (BIT(13) << 13) | (BITS(11:1) << 2) );
        flags = (PRED_NE0 + BITS(23:22)) | // PRED_NE0|PRED_GE0|PRED_EQ0|PRED_LE0
                (BIT(12)? JMP_T : JMP_NT);
        return Hex_jump;
    }
    if( BITS(27:25) == 0b001 && BITS(23:22) == 0 && BITS(13:5) == 0 )
    {
        // Cd32/Gd32 = Rs32
        uint32_t dbl = BIT(24)? REG_DOUBLE : 0;
        op_reg( ops[0], (BIT(21)? REG_C0 : REG_G0) + d5, dbl );
        op_reg( ops[1], REG_R(s5), dbl );
        return Hex_mov;
    }
    if( BITS(27:26) == 0b10 && BITS(24:22) == 0 && BITS(13:5) == 0 )
    {
        // Rd32 = Cs32/Gs32
        uint32_t dbl = BIT(25)? 0 : REG_DOUBLE;
        op_reg( ops[0], REG_R(d5), dbl );
        op_reg( ops[1], (BIT(21)? REG_G0 : REG_C0) + s5, dbl );
        return Hex_mov;
    }
    if( BITS(27:24) == 0b1001 && BIT(13) == 0 && BIT(2) == 0 )
    {
        // p3 = sp{1-3}loop0(Ii,#II) or loop{0|1}(Ii,#II)
        uint32_t type = loops[ BITS(23:21) ], rp = 0;
        if( !type ) return 0;
        if( type >= Hex_sp1loop0 )
            op_reg( ops[rp++], REG_P(3) );
        op_pcrel( ops[rp], EXTEND( (SBITS(12:8) << 2) | BITS(4:3), 2 ) );
        op_imm( ops[rp+1], (BITS(20:16) << 5) | (BITS(7:5) << 2) | BITS(1:0) );
        return type;
    }
    if( BITS(27:16) == 0b101001001001 && BIT(13) == 0 && BITS(6:5) == 0 )
    {
        // Rd32 = add(pc,#Ii)
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_PC );
        op_imm_ex( ops[2], s_pkt_start + EXTEND( BITS(12:7), 0 ), IMM_PCREL | (extended? IMM_EXTENDED : 0) );
        return Hex_add;
    }
    if( BITS(27:24) == 0b1011 && BITS(19:18) == 0 && BITS(13:10) == 0 && BITS(5:2) == 0 )
    {
        // Pd4 = <logical>(Ps4,Pt4,Pu4)
        static const uint8_t ins[16][2] = {
            { Hex_and,  2 }, { Hex_and_and, 3  }, { Hex_or,   2 }, { Hex_and_or, 3  },
            { Hex_xor,  2 }, { Hex_or_and,  3  }, { Hex_and,  6 }, { Hex_or_or,  3  },
            { Hex_any8, 1 }, { Hex_and_and, 11 }, { Hex_all8, 1 }, { Hex_and_or, 11 },
            { Hex_not,  1 }, { Hex_or_and,  11 }, { Hex_or,   6 }, { Hex_or_or,  11 },
        };
        uint32_t code = BITS(23:20), n = ins[code][1] & 3;
        uint32_t sn = ins[code][1] & 4, un = ins[code][1] & 8;
        if( n == 1 && (u2 | t2) != 0 || n == 2 && u2 != 0 ) return 0;
        // swap the arguments of 'xor'
        if( code == 4 ) SWAP(t2, s2);

        op_reg( ops[0], REG_P(d2) );
        if( n == 1 ) {
            op_reg( ops[1], REG_P(s2), sn? REG_PRE_NOT : 0 );
        }
        else if( n == 2 ) {
            op_reg( ops[1], REG_P(t2) );
            op_reg( ops[2], REG_P(s2), sn? REG_PRE_NOT : 0 );
        }
        else if( n == 3 ) {
            op_reg( ops[1], REG_P(s2), sn? REG_PRE_NOT : 0 );
            op_reg( ops[2], REG_P(t2) );
            op_reg( ops[3], REG_P(u2), un? REG_PRE_NOT : 0 );
        }
        return ins[code][0];
    }
    if( BITS(27:21) == 0b1011000 && BITS(19:18) == 0 && BITS(13:10) == 0b1000 && BITS(7:2) == 0b100100 )
    {
        // Pd4 = [!]fastcorner9(Ps4,Pt4)
        op_reg( ops[0], REG_P(d2) );
        op_reg( ops[1], REG_P(s2) );
        op_reg( ops[2], REG_P(t2) );
        flags = BIT(20)? IAT_NOT : 0;
        return Hex_fastcorner9;
    }
    if( BITS(27:21) == 0b0010010 && BIT(13) == 0 && BIT(7) == 0 && BITS(4:0) == 0 )
    {
        // trace(Rs32), diag[0|1](Rs32,Rt32)
        uint32_t t5 = BITS(12:8), code = BITS(6:5);
        uint32_t dbl = BIT(6)? REG_DOUBLE : 0;
        if( !dbl && t5 ) return 0;
        op_reg( ops[0], REG_R(s5), dbl );
        if( dbl ) op_reg( ops[1], REG_R(t5), dbl );
        return code == 0? Hex_trace :
               code == 1? Hex_diag :
               code == 2? Hex_diag0 : Hex_diag1;
    }
    return 0;
}

static uint32_t iclass_7_ALU2op( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), d5 = BITS(4:0);
    bool extended = extender != 0;

    switch( BITS(27:24) )
    {
    case 0b0000:
        if( BITS(13:5) == 0 )
        {
            // Rd32 = {aslh|asrh|sxtb|sxth|zxth}(Rs32)
            static const uint8_t itypes[8] = { Hex_aslh, Hex_asrh, 0, Hex_mov, 0, Hex_sxtb, Hex_zxth, Hex_sxth };
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            return itypes[ BITS(23:21) ];
        }
        if( BITS(13:12) == 0b10 && BITS(7:5) == 0 )
        {
            // if ([!]Pu4[.new]) Rd32 = {aslh|asrh|sxtb|zxtb|sxth|zxth}(Rs32)
            static const uint8_t itypes[8] = { Hex_aslh, Hex_asrh, 0, 0, Hex_zxtb, Hex_sxtb, Hex_zxth, Hex_sxth };
            op_reg( ops[PRED_A], REG_P(BITS(9:8)),
                    (BIT(10)? REG_POST_NEW : 0) |
                    (BIT(11)? REG_PRE_NOT : 0) );
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            flags = PRED_REG;
            return itypes[ BITS(23:21) ];
        }
        break;

    case 0b0001:
    case 0b0010:
        if( BIT(21) == 1 )
        {
            // Rx32.{l|h} = #Ii
            op_reg( ops[0], REG_R(s5), BIT(24)? REG_POST_LO : REG_POST_HI );
            op_imm( ops[1], (BITS(23:22) << 14) | BITS(13:0) );
            return Hex_mov;
        }
        break;

    case 0b0011:
        if( BIT(13) == 0 )
        {
            // Rd32 = mux(Pu4,#Ii,Rs32) or mux(Pu4,Rs32,#Ii)
            int32_t imm = EXTEND( SBITS(12:5), 0 );
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_P(BITS(22:21)) );
            if( BIT(23) ) {
                op_imm( ops[2], imm, true, extended );
                op_reg( ops[3], REG_R(s5) );
            } else {
                op_reg( ops[2], REG_R(s5) );
                op_imm( ops[3], imm, true, extended );
            }
            return Hex_mux;
        }
        if( BIT(23) == 0 && BIT(13) == 1 )
        {
            // Rdd32 = combine(Rs32,#Ii) or Rd32 = [!]cmp.eq(Rs32,#Ii)
            int32_t code = BITS(22:21), imm = EXTEND( SBITS(12:5), 0 );
            op_reg( ops[0], REG_R(d5), BIT(22)? 0 : REG_DOUBLE );
            if( code == 1 ) {
                op_imm( ops[1], imm, true, extended );
                op_reg( ops[2], REG_R(s5) );
            } else {
                op_reg( ops[1], REG_R(s5) );
                op_imm( ops[2], imm, true, extended );
            }
            if( code == 3 ) flags = IAT_NOT;
            return BIT(22)? Hex_cmp : Hex_combine;
        }
        break;

    case 0b0100: {
            // if ([!]Pu4[.new]) Rd32 = add(Rs32,#Ii)
            op_reg( ops[PRED_A], REG_P(BITS(22:21)),
                    (BIT(13)? REG_POST_NEW: 0) |
                    (BIT(23)? REG_PRE_NOT: 0) );
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], EXTEND( SBITS(12:5), 0 ), true, extended );
            flags = PRED_REG;
            return Hex_add;
        }

    case 0b0101:
        if( BIT(23) == 0 && BITS(3:2) == 0 )
        {
            // Pd4 = [!]cmp%c(Rs32,#Ii)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], EXTEND( (SBIT(21) << 9) | BITS(13:5), 0 ), true, extended );
            flags = (BIT(22)? CMP_GT : CMP_EQ) | (BIT(4)? IAT_NOT : 0);
            return Hex_cmp;
        }
        if( BITS(23:21) == 0b100 && BITS(3:2) == 0 )
        {
            // Pd4 = [!]cmp%c(Rs32,#Ii)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], EXTEND( BITS(13:5), 0 ), false, extended );
            flags = CMP_GTU | (BIT(4)? IAT_NOT : 0);
            return Hex_cmp;
        }
        break;

    case 0b0110: {
            // Rd32 = {and|or}(Rs32,#Ii) or Rd32 = sub(#Ii,Rs32)
            static const uint8_t itypes[4] = { Hex_and, Hex_sub, Hex_or, 0 };
            int32_t imm = EXTEND( (SBIT(21) << 9) | BITS(13:5), 0 );
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], imm, true, extended );
            return itypes[ BITS(23:22) ];
        }

    case 0b1000:
        if( BIT(21) == 0 )
        {
            // Rd32 = #Ii
            int32_t imm = EXTEND( (SBITS(23:22) << 14) | (BITS(20:16) << 9) | BITS(13:5), 0);
            op_reg( ops[0], REG_R(d5) );
            op_imm( ops[1], imm, true, extended );
            return Hex_mov;
        }
        break;

    case 0b1010:
    case 0b1011: {
            // Rd32 = mux(Pu4,#Ii,#II)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_P(BITS(24:23)) );
            op_imm( ops[2], EXTEND( SBITS(12:5), 0 ), true, extended );
            op_imm( ops[3], (SBITS(22:16) << 1) | BIT(13), true );
            return Hex_mux;
        }

    case 0b1100:
        if( BIT(23) == 0 )
        {
            // Rdd32 = combine(#Ii,#II)
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_imm( ops[1], EXTEND( SBITS(12:5), 0 ), true, extended );
            op_imm( ops[2], (SBITS(22:16) << 1) | BIT(13), true );
            return Hex_combine;
        }
        if( BITS(23:21) == 0b100 )
        {
            // Rdd32 = combine(#Ii,#II)
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_imm( ops[1], SBITS(12:5), true );
            op_imm( ops[2], EXTEND( (BITS(20:16) << 1) | BIT(13), 0 ), false, extended );
            return Hex_combine;
        }
        break;

    case 0b1110:
        if( BIT(20) == 0 )
        {
            // if ([!]Pu4[.new]) Rd32 = #Ii
            op_reg( ops[PRED_A], REG_P(BITS(22:21)),
                    (BIT(13)? REG_POST_NEW: 0) |
                    (BIT(23)? REG_PRE_NOT: 0) );
            op_reg( ops[0], REG_R(d5) );
            op_imm( ops[1], EXTEND( (SBITS(19:16) << 8) | BITS(12:5), 0 ), true, extended );
            flags = PRED_REG;
            return Hex_mov;
        }
        break;

    case 0b1111:
        if( BITS(23:16) == 0 && BITS(13:0) == 0 )
            return Hex_nop;
        break;
    }
    return 0;
}

static uint32_t iclass_8_S2op( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t code, s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);

    switch( BITS(27:24) )
    {
    case 0b0000:
        if( BIT(21) == 0 && BIT(7) == 0 )
        {
            // Rdd32 = <shift>(Rss32,#Ii)
            static const uint16_t itypes[16] = {
                Hex_asr,    Hex_lsr,    Hex_asl,   Hex_rol,
                Hex_svasrw, Hex_svlsrw, Hex_svaslw, 0,
                Hex_svasrh, Hex_svlsrh, Hex_svaslh, 0,
            };
            if( (BITS(13:8) >> (6 - BITS(23:22))) != 0 ) return 0;
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BITS(13:8) );
            return itypes[ (BITS(23:22) << 2) | BITS(6:5) ];
        }
        if( BITS(23:21) == 0b001 && BITS(13:12) == 0 && BITS(7:5) == 0 )
        {
            // Rdd32 = vasrh(Rss32,#Ii):rnd [mapped from raw]
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BITS(11:8) + 1 );
            flags = IPO_RND;
            return Hex_svasrh;
        }
        if( BITS(23:21) == 0b110 && BITS(7:5) == 0b111 )
        {
            // Rdd32 = asr(Rss32,#Ii):rnd
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BITS(13:8) );
            flags = IPO_RND;
            return Hex_asr;
        }
        break;

    case 0b0001:
    case 0b0011:
    case 0b1010: {
            // Rdd32 = {insert|extract[u]}(Rss32,#Ii,#II)
            static const uint8_t itypes[4] = { 0, Hex_extractu3, Hex_extract3, Hex_insert3 };
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BITS(13:8) );
            op_imm( ops[3], (BITS(23:21) << 3) | BITS(7:5) );
            return itypes[ BITS(25:24) ];
        }

    case 0b0010:
    case 0b1110:
        if( BIT(21) == 0 )
        {
            // Rx[x]32 *= {asr|lsr|asl|rol}(Rs[s]32,#Ii)
            static const uint8_t itypes[4] = { Hex_asr, Hex_lsr, Hex_asl, Hex_rol };
            static const uint8_t ass[8] = { IAT_SUB, IAT_ADD, IAT_AND, IAT_OR, IAT_XOR };
            bool dbl = BIT(26) == 0;
            flags = ass[(BITS(23:22) << 1) | BIT(7)];
            if( !flags || !dbl && BIT(13) ) return 0;

            op_reg( ops[0], REG_R(d5), dbl? REG_DOUBLE : 0 );
            op_reg( ops[1], REG_R(s5), dbl? REG_DOUBLE : 0 );
            op_imm( ops[2], BITS(13:8) );
            return itypes[ BITS(6:5) ];
        }
        break;

    case 0b0101:
        if( BITS(23:22) == 0b00 && BIT(13) == 0 && BITS(7:2) == 0 )
        {
            // Pd4 = [!]tstbit(Rs32,#Ii)
            op_reg( ops[0], REG_P(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], BITS(12:8) );
            flags = BIT(21)? IAT_NOT : 0;
            return Hex_tstbit;
        }
        if( BITS(23:21) == 0b010 && BITS(13:2) == 0 )
        {
            // Pd4 = Rs32
            op_reg( ops[0], REG_P(d5) );
            op_reg( ops[1], REG_R(s5) );
            return Hex_mov;
        }
        if( BITS(23:22) == 0b10 && BITS(7:2) == 0 )
        {
            // Pd4 = [!]bitsclr(Rs32,#Ii)
            op_reg( ops[0], REG_P(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], BITS(13:8) );
            flags = BIT(21)? IAT_NOT : 0;
            return Hex_bitsclr;
        }
        if( BITS(23:21) == 0b111 && BIT(13) == 0 && BITS(7:2) == 0 )
        {
            // Pd4 = sfclass(Rs32,#Ii)
            op_reg( ops[0], REG_P(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], BITS(12:8) );
            return Hex_sfclass;
        }
        break;

    case 0b0110:
        if( BITS(23:16) == 0 && BITS(13:10) == 0 && BITS(7:5) == 0 )
        {
            // Rdd32 = mask(Pt4)
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_P(t5) );
            return Hex_mask;
        }
        break;

    case 0b0111: {
            // Rx32 = tableidx{b|h|w|d}(Rs32,#Ii,#II)
            static const uint16_t sz[4] = { SZ_B, SZ_H, SZ_W, SZ_D };
            flags = sz[ BITS(23:22) ];
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], (BIT(21) << 3) | BITS(7:5) );
            op_imm( ops[3], SBITS(13:8) + BITS(23:22), true );
            return Hex_tableidx;
        }

    case 0b1000:
        if( BITS(23:21) == 0b011 && BITS(13:12) == 0 && BITS(7:6) == 0b10 )
        {
            // Rd32 = vasrhub(Rss32,#Ii)[:rnd]:sat
            uint32_t imm = BITS(11:8);
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BIT(5)? imm : imm + 1 );
            flags = BIT(5)? IPO_SAT : IPO_RND_SAT; // mapped from raw
            return Hex_svasrhub;
        }
        if( BITS(23:21) == 0b011 && BITS(7:5) == 0b010 )
        {
            // Rd32 = add(clb(Rss32),#Ii)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], SBITS(13:8), true );
            return Hex_add_clb;
        }
        break;

    case 0b1100:
        if( BITS(23:21) == 0b001 && BITS(7:5) == 0 )
        {
            // Rd32 = add(clb(Rs32),#Ii)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], SBITS(13:8), true );
            return Hex_add_clb;
        }
        if( BITS(23:21) == 0b111 && BITS(7:5) == 2 )
        {
            // Rdd32 = cround(Rss32,#Ii)
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BITS(13:8) );
            return Hex_cround;
        }
        break;

    case 0b1001:
        if( BITS(23:18) == 0b000000 && BITS(13:10) == 0 && BITS(7:5) == 0 )
        {
            // Rd32 = vitpack(Ps4,Pt4)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_P(s5) );
            op_reg( ops[2], REG_P(t5) );
            return Hex_svitpack;
        }
        if( BITS(23:18) == 0b010000 && BITS(13:5) == 0 )
        {
            // Rd32 = Ps4
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_P(s5) );
            return Hex_mov;
        }
        break;

    case 0b1011:
        if( BITS(23:21) == 0b111 && BITS(13:7) == 0 )
        {
            // Rd32,Pe4 = sfinvsqrta(Rs32)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_P(BITS(6:5)) );
            op_reg( ops[2], REG_R(s5) );
            return Hex_sfinvsqrta;
        }
        break;

    case 0b1101:
        if( BIT(23) == 0 && s5 == 0 && BIT(13) == 1 )
        {
            // Rd32 = mask(#Ii,#II)
            op_reg( ops[0], REG_R(d5) );
            op_imm( ops[1], BITS(12:8) );
            op_imm( ops[2], (BITS(22:21) << 3) | BITS(7:5) );
            return Hex_mask2;
        }
        if( BIT(13) == 0 )
        {
            // Rd32 = extract[u](Rs32,#Ii,#II)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], BITS(12:8) );
            op_imm( ops[3], (BITS(22:21) << 3) | BITS(7:5) );
            return BIT(23)? Hex_extract3 : Hex_extractu3;
        }
        break;

    case 0b1111:
        if( BIT(23) == 0 && BIT(13) == 0 )
        {
            // Rd32 = insert(Rs32,#Ii,#II)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], BITS(12:8) );
            op_imm( ops[3], (BITS(22:21) << 3) | BITS(7:5) );
            return Hex_insert3;
        }
        break;
    }

    // Rd[d]32 = <op>(Rs[s]32, #u5)
    if( BIT(27) == 1 && BITS(25:24) == 0 && BIT(13) == 0 )
    {
        uint32_t dreg = 0;
        switch( (BIT(26) << 6) | (BITS(23:21) << 3) | BITS(7:5) )
        {
        case 0b0110010: code = Hex_svasrw, dreg = SS; break;
        case 0b0110100: code = Hex_bitsplit, dreg = DD; break;
        case 0b0110101: code = Hex_clip; break;
        case 0b0110110: code = Hex_svclip, dreg = DD|SS; break;
        case 0b1000000: code = Hex_asr; break;
        case 0b1000001: code = Hex_lsr; break;
        case 0b1000010: code = Hex_asl; break;
        case 0b1000011: code = Hex_rol; break;
        case 0b1010000: code = Hex_asr, flags = IPO_RND; break;
        case 0b1010010: code = Hex_asl, flags = IPO_SAT; break;
        case 0b1110000: code = Hex_setbit2; break;
        case 0b1110001: code = Hex_clrbit2; break;
        case 0b1110010: code = Hex_togglebit; break;
        case 0b1111000: code = Hex_cround; break;
        case 0b1111100: code = Hex_round2; break;
        case 0b1111110: code = Hex_round2, flags = IPO_SAT; break;
        default: goto __next;
        }
        op_reg( ops[0], REG_R(d5), FLG_D(dreg) );
        op_reg( ops[1], REG_R(s5), FLG_S(dreg) );
        op_imm( ops[2], BITS(12:8) );
        return code;
    }

__next:
    // Rd[d]32 = <op>(Rs[s]32)
    if( BITS(13:8) == 0 )
    {
        switch( (BITS(27:21) << 3) | BITS(7:5) )
        {
        // dd,ss
        case 0b0000000100: code = Hex_svsathub; break;
        case 0b0000000101: code = Hex_svsatwuh; break;
        case 0b0000000110: code = Hex_svsatwh; break;
        case 0b0000000111: code = Hex_svsathb; break;
        case 0b0000010100: code = Hex_svabsh; break;
        case 0b0000010101: code = Hex_svabsh, flags = IPO_SAT; break;
        case 0b0000010110: code = Hex_svabsw; break;
        case 0b0000010111: code = Hex_svabsw, flags = IPO_SAT; break;
        case 0b0000100100: code = Hex_not; break;
        case 0b0000100101: code = Hex_neg; break;
        case 0b0000100110: code = Hex_abs; break;
        case 0b0000100111: code = Hex_svconj, flags = IPO_SAT; break;
        case 0b0000110100: code = Hex_deinterleave; break;
        case 0b0000110101: code = Hex_interleave; break;
        case 0b0000110110: code = Hex_brev; break;
        case 0b0000111000: code = Hex_conv_df2d; break;
        case 0b0000111001: code = Hex_conv_df2ud; break;
        case 0b0000111010: code = Hex_conv_ud2df; break;
        case 0b0000111011: code = Hex_conv_d2df; break;
        case 0b0000111110: code = Hex_conv_df2d, flags = IPO_CHOP; break;
        case 0b0000111111: code = Hex_conv_df2ud, flags = IPO_CHOP; break;
        // dd,s
        case 0b0100000000: code = Hex_svsxtbh; break;
        case 0b0100000010: code = Hex_svzxtbh; break;
        case 0b0100000100: code = Hex_svsxthw; break;
        case 0b0100000110: code = Hex_svzxthw; break;
        case 0b0100010000: code = Hex_sxtw; break;
        case 0b0100010010: code = Hex_svsplath; break;
        case 0b0100010100: code = Hex_svsplatb; break;
        case 0b0100100000: code = Hex_conv_sf2df; break;
        case 0b0100100001: code = Hex_conv_uw2df; break;
        case 0b0100100010: code = Hex_conv_w2df; break;
        case 0b0100100011: code = Hex_conv_sf2ud; break;
        case 0b0100100100: code = Hex_conv_sf2d; break;
        case 0b0100100101: code = Hex_conv_sf2ud, flags = IPO_CHOP; break;
        case 0b0100100110: code = Hex_conv_sf2d, flags = IPO_CHOP; break;
        // d,ss
        case 0b1000000000: code = Hex_svsathub; break;
        case 0b1000000001: code = Hex_conv_df2sf; break;
        case 0b1000000010: code = Hex_svsatwh; break;
        case 0b1000000100: code = Hex_svsatwuh; break;
        case 0b1000000110: code = Hex_svsathb; break;
        case 0b1000001001: code = Hex_conv_ud2sf; break;
        case 0b1000010000: code = Hex_clb; break;
        case 0b1000010001: code = Hex_conv_d2sf; break;
        case 0b1000010010: code = Hex_cl0; break;
        case 0b1000010100: code = Hex_cl1; break;
        case 0b1000011000: code = Hex_normamt; break;
        case 0b1000011001: code = Hex_conv_df2uw; break;
        case 0b1000011011: code = Hex_popcount; break;
        case 0b1000100000: code = Hex_svtrunohb; break;
        case 0b1000100001: code = Hex_conv_df2w; break;
        case 0b1000100010: code = Hex_svtrunehb; break;
        case 0b1000100100: code = Hex_svrndwh; break;
        case 0b1000100110: code = Hex_svrndwh, flags = IPO_SAT; break;
        case 0b1000101001: code = Hex_conv_df2uw, flags = IPO_CHOP; break;
        case 0b1000110000: code = Hex_sat; break;
        case 0b1000110001: code = Hex_round, flags = IPO_SAT; break;
        case 0b1000111001: code = Hex_conv_df2w, flags = IPO_CHOP; break;
        case 0b1000111010: code = Hex_ct0; break;
        case 0b1000111100: code = Hex_ct1; break;
        // d,s
        case 0b1011001000: code = Hex_conv_uw2sf; break;
        case 0b1011010000: code = Hex_conv_w2sf; break;
        case 0b1011011000: code = Hex_conv_sf2uw; break;
        case 0b1011011001: code = Hex_conv_sf2uw, flags = IPO_CHOP; break;
        case 0b1011100000: code = Hex_conv_sf2w; break;
        case 0b1011100001: code = Hex_conv_sf2w, flags = IPO_CHOP; break;
        case 0b1011101000: code = Hex_sffixupr; break;
        // d,s
        case 0b1100000100: code = Hex_clb; break;
        case 0b1100000101: code = Hex_cl0; break;
        case 0b1100000110: code = Hex_cl1; break;
        case 0b1100000111: code = Hex_normamt; break;
        case 0b1100010100: code = Hex_ct0; break;
        case 0b1100010101: code = Hex_ct1; break;
        case 0b1100010110: code = Hex_brev; break;
        case 0b1100010111: code = Hex_svsplatb; break;
        case 0b1100100000: code = Hex_svsathb; break;
        case 0b1100100010: code = Hex_svsathub; break;
        case 0b1100100100: code = Hex_abs; break;
        case 0b1100100101: code = Hex_abs, flags = IPO_SAT; break;
        case 0b1100100110: code = Hex_neg, flags = IPO_SAT; break;
        case 0b1100100111: code = Hex_swiz; break;
        case 0b1100110100: code = Hex_sat, flags = SZ_H; break;
        case 0b1100110101: code = Hex_sat, flags = SZ_UH; break;
        case 0b1100110110: code = Hex_sat, flags = SZ_UB; break;
        case 0b1100110111: code = Hex_sat, flags = SZ_B; break;
        default: goto __next2;
        }
        op_reg( ops[0], REG_R(d5), BIT(27) == 0? REG_DOUBLE : 0 );
        op_reg( ops[1], REG_R(s5), BITS(26:24) == 0? REG_DOUBLE : 0 );
        return code;
    }
__next2:
    return 0;
}

static const uint8_t mtypes_cl9[16][3] = {
    { 255 },                    { MEM_BH, 1, 0 },  { MEM_H | MEM_FIFO, 1, 1 }, { MEM_UBH, 1, 0 },
    { MEM_B | MEM_FIFO, 0, 1 }, { MEM_UBH, 2, 1 }, { 255 },                    { MEM_BH, 2, 1 },
    { MEM_B, 0, 0 },            { MEM_UB, 0, 0 },  { MEM_H, 1, 0 },            { MEM_UH, 1, 0 },
    { MEM_W, 2, 0 },            { 255 },           { MEM_D, 3, 1 },            { 255 },
};

static uint32_t iclass_9_LD( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), d5 = BITS(4:0);
    const uint8_t *mtype = mtypes_cl9[ BITS(24:21) ];
    bool extended = extender != 0;

    if( BIT(27) == 0 && mtype[0] != 255 )
    {
        // Rd32 = memXX(Rs32+#Ii)
        int32_t imm = EXTEND( (SBITS(26:25) << 9) | BITS(13:5), mtype[1] );
        op_reg( ops[0], REG_R(d5), mtype[2]? REG_DOUBLE : 0 );
        op_mem_ind( ops[1], mtype[0], REG_R(s5), imm, extended );
        return Hex_mov;
    }
    if( BITS(27:24) == 0b1011 && mtype[0] != 255 && BIT(13) == 1 )
    {
        // if ([!]Pt4[.new]) Rd32 = memXX(Rx32++#Ii)
        op_reg( ops[PRED_A], REG_P(BITS(10:9)),
                (BIT(11)? REG_PRE_NOT : 0) |
                (BIT(12)? REG_POST_NEW : 0) );
        op_reg( ops[0], REG_R(d5), mtype[2]? REG_DOUBLE : 0 );
        op_mem_inc( ops[1], o_mem_inc_imm, mtype[0], REG_R(s5), SBITS(8:5) << mtype[1] );
        flags = PRED_REG;
        return Hex_mov;
    }
    if( BIT(27) == 1 && mtype[0] != 255 && BITS(12:10) == 0 )
    {
        // Rd32 = memXX(Rx32++...)
        static const uint8_t otypes[8] = { o_mem_circ_imm, o_mem_inc_imm, o_mem_inc_reg, o_mem_inc_brev, o_mem_circ_reg };
        uint32_t otype = otypes[ (BIT(9) << 2) | BITS(26:25) ];
        int32_t imm = SBITS(8:5) << mtype[1], mu = BIT(13);
        bool has_mu = otype != o_mem_inc_imm, has_imm = otype == o_mem_inc_imm || otype == o_mem_circ_imm;
        if( !otype || !has_mu && mu || !has_imm && imm )
            return 0;

        op_reg( ops[0], REG_R(d5), mtype[2]? REG_DOUBLE : 0 );
        op_mem_inc( ops[1], otype, mtype[0], REG_R(s5), imm, mu? REG_M1 : REG_M0 );
        return Hex_mov;
    }
    if( BITS(27:21) == 0b0000000 && BITS(13:5) == 0 )
    {
        // Rdd32 = deallocframe(Rs32):raw
        if( REG_R(d5) == REG_FP && REG_R(s5) == REG_FP )
            return Hex_deallocframe; // simplify
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5) );
        return Hex_deallocframe_raw;
    }
    if( BITS(27:21) == 0b0110000 && BIT(10) == 0 && BITS(7:5) == 0 )
    {
        // [if ([!]Pv4[.new])] Rdd32 = dealloc_return(Rs32)%t:raw
        uint32_t cond = BITS(13:11);
        if( cond == 4 || cond == 0 && BITS(9:8) != 0 ) return 0;
        if( cond ) {
            op_reg( ops[PRED_A], REG_P(BITS(9:8)),
                    (BIT(13)? REG_PRE_NOT : 0) |
                    (BIT(11)? REG_POST_NEW : 0) );
            flags = PRED_REG |
                    (BITS(12:11) == 3? JMP_T : BITS(12:11) == 1? JMP_NT : 0);
        }
        if( REG_R(d5) == REG_FP && REG_R(s5) == REG_FP )
            return Hex_return; // simplify
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5) );
        return Hex_return_raw;
    }
    if( BITS(27:21) == 0b0010000 && BIT(13) == 0 && BITS(11:5) == 0 )
    {
        // Rd32 = memX_locked(Rs32)
        op_reg( ops[0], REG_R(d5), BIT(12)? REG_DOUBLE : 0 );
        op_mem_locked( ops[1], BIT(12)? MEM_D : MEM_W, REG_R(s5) );
        return Hex_mov;
    }
    if( BITS(27:21) == 0b0010000 && BIT(13) == 1 && BITS(7:5) == 0 )
    {
        // Rd32 = memw_phys(Rs32,Rt32)
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(BITS(12:8)) );
        return Hex_ldphys;
    }
    if( BITS(27:21) == 0b0010000 && BITS(7:0) == 0b01000000 )
    {
        // memcpy(Rs32,Rt32,Mu2)
        op_reg( ops[0], REG_R(s5) );
        op_reg( ops[1], REG_R(BITS(12:8)) );
        op_reg( ops[2], REG_P(BIT(13)) );
        return Hex_memcpy;
    }
    if( BITS(27:21) == 0b0100000 && BITS(13:11) == 0 )
    {
        // dcfetch(Rs32+#Ii)
        op_reg_off( ops[0], REG_R(s5), BITS(10:0) << 3 );
        return Hex_dcfetch;
    }
    return 0;
}

static uint32_t iclass_9_LD_EXT( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    // all instructions below must extend
    if( !extender ) return 0;
    uint32_t s5 = BITS(20:16), d5 = BITS(4:0);
    const uint8_t *mtype = mtypes_cl9[ BITS(24:21) ];

    if( BITS(27:25) == 0b101 && mtype[0] != 255 && BITS(13:12) == 0b01 && BIT(7) == 0 )
    {
        // Rd32 = memXX(Re32=#II)
        uint32_t imm = MUST_EXTEND( (BITS(11:8) << 2) | BITS(6:5) );
        op_reg( ops[0], REG_R(d5), mtype[2]? REG_DOUBLE : 0 );
        op_mem_abs_set( ops[1], mtype[0], REG_R(s5), imm );
        return Hex_mov;
    }
    if( BITS(27:25) == 0b110 && mtype[0] != 255 && BIT(12) == 1 )
    {
        // Rd32 = memXX(Rt32<<#Ii+#II)
        uint32_t u2 = (BIT(13) << 1) | BIT(7);
        uint32_t imm = MUST_EXTEND( (BITS(11:8) << 2) | BITS(6:5) );
        op_reg( ops[0], REG_R(d5), mtype[2]? REG_DOUBLE : 0 );
        op_mem_abs_off( ops[1], mtype[0], REG_R(s5), u2, imm );
        return Hex_mov;
    }
    if( BITS(27:24) == 0b1111 && mtype[0] != 255 && BIT(13) == 1 && BITS(7:5) == 0b100 )
    {
        // if ([!]Pt4[.new]) Rd32 = memXX(#II)
        uint32_t imm = MUST_EXTEND( (BITS(20:16) << 1) | BIT(8) );
        op_reg( ops[PRED_A], REG_P(BITS(10:9)),
                (BIT(11)? REG_PRE_NOT : 0) |
                (BIT(12)? REG_POST_NEW : 0) );
        op_reg( ops[0], REG_R(d5), mtype[2]? REG_DOUBLE : 0 );
        op_mem_abs( ops[1], mtype[0], imm );
        flags = PRED_REG;
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_10_ST( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8);
    uint32_t code = BITS(23:21), code_nv = BITS(12:11);
    uint32_t type = code != 5? types_st[ code ] : types_nv[ code_nv ];
    bool extended = extender != 0;

    if( BITS(27:21) == 0b0000100 && BITS(13:11) == 0 )
    {
        // allocframe(Rx32,#Ii):raw
        if( REG_R(s5) == REG_SP ) { // simplify
            op_imm( ops[0], BITS(10:0) << 3 );
            return Hex_allocframe;
        } else {
            op_reg( ops[0], REG_R(s5) );
            op_imm( ops[1], BITS(10:0) << 3 );
            return Hex_allocframe_raw;
        }
    }
    if( BIT(27) == 0 && BIT(24) == 1 && type != 255 )
    {
        // memX(Rs32+#Ii) = Rt32[.h|.new]
        int32_t imm = EXTEND( (SBITS(26:25) << 9) | (BIT(13) << 8) | BITS(7:0), mem_shift( type ) );
        op_mem_ind( ops[0], type, REG_R(s5), imm, extended );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                code == 5? REG_POST_NEW :
                code == 3? REG_POST_HI :
                code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    if( BITS(27:24) == 0b1011 && BIT(13) == 1 && type != 255 )
    {
        // if ([!]Pt4[.new]) memX(Rx32++#Ii) = Rt[t]32[.h|.new]
        op_reg( ops[PRED_A], REG_P(BITS(1:0)),
                (BIT(2)? REG_PRE_NOT : 0) |
                (BIT(7)? REG_POST_NEW : 0) );
        op_mem_inc( ops[0], o_mem_inc_imm, type, REG_R(s5), SBITS(6:3) << mem_shift( type ) );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                code == 5? REG_POST_NEW :
                code == 3? REG_POST_HI :
                code == 6? REG_DOUBLE : 0 );
        flags = PRED_REG;
        return Hex_mov;
    }
    if( BIT(27) == 1 && BIT(24) == 1 && BIT(7) == 0 && BIT(2) == 0 && BIT(0) == 0 && type != 255 )
    {
        // memX(Rx32++...) = Rt[t]32[.h|.new]
        static const uint8_t otypes[8] = { o_mem_circ_imm, o_mem_inc_imm, o_mem_inc_reg, o_mem_inc_brev, o_mem_circ_reg };
        uint32_t otype = otypes[ (BIT(1) << 2) | BITS(26:25) ];
        int32_t imm = SBITS(6:3) << mem_shift( type ), mu = BIT(13);
        bool has_mu = otype != o_mem_inc_imm, has_imm = otype == o_mem_inc_imm || otype == o_mem_circ_imm;
        if( !otype || !has_mu && mu || !has_imm && imm )
            return 0;

        op_mem_inc( ops[0], otype, type, REG_R(s5), imm, mu? REG_M1 : REG_M0 );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                code == 5? REG_POST_NEW :
                code == 3? REG_POST_HI :
                code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    if( BITS(27:23) == 0b00001 && BIT(21) == 1 && BIT(13) == 0 && BITS(7:2) == 0 )
    {
        // memX_locked(Rs32,Pd4) = Rt[t]32
        op_mem_locked( ops[0], BIT(22)? MEM_D : MEM_W, REG_R(s5), REG_P(BITS(1:0)) );
        op_reg( ops[1], REG_R(t5), BIT(22)? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_10_ST_EXT( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    // all instructions here must extend
    if( !extender ) return 0;

    uint32_t s5 = BITS(20:16), t5 = BITS(12:8);
    uint32_t code = BITS(23:21), code_nv = BITS(12:11);
    uint32_t type = code != 5? types_st[ code ] : types_nv[ code_nv ];

    if( BITS(27:24) == 0b1011 && BIT(13) == 0 && type != 255 && BITS(7:6) == 0b10 )
    {
        // memX(Re32=#II) = Rt[t]32[.h|.new]
        uint32_t imm = MUST_EXTEND( BITS(5:0) );
        op_mem_abs_set( ops[0], type, REG_R(s5), imm );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                code == 5? REG_POST_NEW :
                code == 3? REG_POST_HI :
                code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    if( BITS(27:24) == 0b1101 && type != 255 && BIT(7) == 1 )
    {
        // memX(Ru32<<#Ii+#II) = Rt[t]32[.h|.new]
        uint32_t u2 = (BIT(13) << 1) | BIT(6);
        uint32_t imm = MUST_EXTEND( BITS(5:0) );
        op_mem_abs_off( ops[0], type, REG_R(s5), u2, imm );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                code == 5? REG_POST_NEW :
                code == 3? REG_POST_HI :
                code == 6? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    if( BITS(27:24) == 0b1111 && BITS(20:18) == 0 && type != 255 && BIT(7) == 1 )
    {
        // if ([!]Pv4[.new]) memX(#II) = Rt[t]32[.h|.new]
        uint32_t imm = MUST_EXTEND( (BITS(17:16) << 4) | BITS(6:3) );
        op_reg( ops[PRED_A], REG_P(BITS(1:0)),
                (BIT(2)? REG_PRE_NOT : 0) |
                (BIT(13)? REG_POST_NEW : 0) );
        op_mem_abs( ops[0], type, imm );
        op_reg( ops[1], code == 5? new_value( BITS(10:8) ) : REG_R(t5),
                code == 5? REG_POST_NEW :
                code == 3? REG_POST_HI :
                code == 6? REG_DOUBLE : 0 );
        flags = PRED_REG;
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_11_ADDI( uint32_t word, uint64_t extender, op_t *ops, uint32_t &/*flags*/ )
{
    bool extended = extender != 0;
    // Rd32 = add(Rs32,#Ii)
    op_reg( ops[0], REG_R( BITS(4:0) ) );
    op_reg( ops[1], REG_R( BITS(20:16) ) );
    op_imm( ops[2], EXTEND( (SBITS(27:21) << 9) | BITS(13:5), 0 ), true, extended );
    return Hex_add;
}

static uint32_t iclass_12_S3op( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);
    uint32_t code = BITS(27:21);

    if( (code & ~0b0010100) == 0b0000000 && BIT(13) == 0 && !(BIT(25) && BIT(7)) )
    {
        // Rdd32 = v{align|splice}b(Rtt32,Rss32,{#Ii|Pu4})
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(t5), REG_DOUBLE );
        if( BIT(25)) op_reg( ops[3], REG_P(BITS(6:5)) );
        else         op_imm( ops[3], BITS(7:5) );
        return BIT(23)? Hex_svspliceb : Hex_svalignb;
    }
    if( (code == 0b0011100 || code == 0b0110010) && BIT(13) == 0 && BIT(5) == 0 )
    {
        // Rd[d]32 = {a|l}s{r|l}(Rs[s]32,Rt32)
        static const uint8_t shifts[4] = { Hex_asr, Hex_lsr, Hex_asl, Hex_lsl };

        op_reg( ops[0], REG_R(d5), BIT(24)? REG_DOUBLE : 0 );
        op_reg( ops[1], REG_R(s5), BIT(24)? REG_DOUBLE : 0 );
        op_reg( ops[2], REG_R(t5) );
        return shifts[ BITS(7:6) ];
    }
    while( (BITS(27:24) == 0b1011 || BITS(27:24) == 0b1100 && BIT(21) == 0) &&
           BIT(13) == 0 && BIT(5) == 0 )
    {
        // Rd[d]32 [|&^-+]= {a|l}s{r|l}(Rs[s]32,Rt32)
        static const uint8_t shifts[4] = { Hex_asr, Hex_lsr, Hex_asl, Hex_lsl };
        static const uint8_t assign[8] = { IAT_OR, 0, IAT_AND, IAT_XOR, IAT_SUB, 0, IAT_ADD, 0 };
        flags = assign[ BITS(23:21) ];
        if( !flags ) break;

        op_reg( ops[0], REG_R(d5), BIT(24)? REG_DOUBLE : 0 );
        op_reg( ops[1], REG_R(s5), BIT(24)? REG_DOUBLE : 0 );
        op_reg( ops[2], REG_R(t5) );
        return shifts[ BITS(7:6) ];
    }
    if( BITS(27:22) == 0b001011 && BIT(13) == 0 && BIT(7) == 0 )
    {
        // Rdd32 = {add|sub}(Rss32,Rtt32,Px4):carry
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(t5), REG_DOUBLE );
        op_reg( ops[3], REG_P(BITS(6:5)) );
        flags = IPO_CARRY;
        return BIT(21)? Hex_subc : Hex_addc;
    }
    if( code == 30 && BITS(7:6) == 0b11 )
    {
        // Rdd32 = vrcrotate(Rss32,Rt32,#Ii)
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(t5) );
        op_imm( ops[3], (BIT(13) << 1) | BIT(5) );
        return Hex_svrcrotate;
    }
    if( code == 93 && BITS(7:6) == 0b00 )
    {
        // Rxx32 += vrcrotate(Rss32,Rt32,#Ii)
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(t5) );
        op_imm( ops[3], (BIT(13) << 1) | BIT(5) );
        flags = IAT_ADD;
        return Hex_svrcrotate;
    }
    if( code == 32 && BIT(13) == 0 )
    {
        // Rd32 = addasl(Rt32,Rs32,#Ii)
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        op_imm( ops[3], BITS(7:5) );
        return Hex_addasl;
    }
    if( code == 40 && BIT(13) == 0 && BIT(7) == 1 )
    {
        // Rd32 = cmpy{i|r}wh(Rss32,Rt32[*]):<<1:rnd:sat
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(t5), BIT(5)? REG_POST_CONJ : 0 );
        flags = IPO_LS1_RND_SAT;
        return BIT(6)? Hex_cmpyrwh : Hex_cmpyiwh;
    }
    if( code == 52 && BIT(13) == 0 && BITS(7:6) == 3 )
    {
        // Rd32 = lsl(#Ii,Rt32)
        op_reg( ops[0], REG_R(d5) );
        op_imm( ops[1], (SBITS(20:16) << 1) | BIT(5), true );
        op_reg( ops[2], REG_R(t5) );
        return Hex_lsl;
    }
    if( 56 <= code && code <= 61 && BIT(13) == 0 && BITS(7:2) == 0 )
    {
        // Pd4 = [!}{tstbit|bitsset|bitsclr}(Rs32,Rt32)
        op_reg( ops[0], REG_P(d5) );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        flags = BIT(21)? IAT_NOT : 0;
        return BIT(22)? Hex_bitsset : BIT(23)? Hex_bitsclr : Hex_tstbit;
    }
    if( code == 62 && BIT(13) == 0 && BITS(4:2) == 0 )
    {
        // Pd4 = cmp%s%c(Rs32,Rt32)
        static const uint32_t cond[8] = {
            ~0u, ~0u, SZ_B | CMP_GT, SZ_H | CMP_EQ,
            SZ_H | CMP_GT, SZ_H | CMP_GTU, SZ_B | CMP_EQ, SZ_B | CMP_GTU
        };
        op_reg( ops[0], REG_P(d5) );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        flags = cond[ BITS(7:5) ];
        return Hex_cmp;
    }
    if( code == 63 && BIT(13) == 0 && BITS(4:2) == 0 )
    {
        // Pd4 = sfcmp%c(Rs32,Rt32)
        static const uint32_t cond[8] = { CMP_GE, CMP_UO, ~0u, CMP_EQ, CMP_GT, ~0u, ~0u, ~0u };
        if( cond[ BITS(7:5) ] == ~0u ) return 0;

        op_reg( ops[0], REG_P(d5) );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        flags = cond[ BITS(7:5) ];
        return Hex_sfcmp;
    }
    if( code == 0b1011001 && (BIT(6) ^ BIT(5)) == 1 )
    {
        // Rxx32 = vr{max|min}%s(Rss32,Ru32)
        static const uint16_t sz[4] = { SZ_H, SZ_W, SZ_UH, SZ_UW };
        // the order of registers is fucked up
        op_reg( ops[0], REG_R(t5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(d5) );
        flags = sz[ (BIT(13) << 1) | BIT(6) ];
        return BIT(7)? Hex_svrmin : Hex_svrmax;
    }

    // all other cases of Rd[d]32 = <op>(Rs[s]32, Rt[t]32)
    uint32_t dreg;
    switch( (code << 4) | (BIT(13) << 3) | BITS(7:5) )
    {
    case 0b00010000000: code = Hex_extractu,   dreg = DD|SS|TT; break;
    case 0b00010000010: code = Hex_shuffeb,    dreg = DD|SS|TT; break;
    case 0b00010000100: code = Hex_shuffob,    dreg = DD|SS|TT; break;
    case 0b00010000110: code = Hex_shuffeh,    dreg = DD|SS|TT; break;

    case 0b00010100000: code = Hex_svxaddsubw, dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b00010100001: code = Hex_svaddhub,   dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b00010100010: code = Hex_svxsubaddw, dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b00010100100: code = Hex_svxaddsubh, dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b00010100110: code = Hex_svxsubaddh, dreg = DD|SS|TT, flags = IPO_SAT; break;

    case 0b00011000000: code = Hex_shuffoh,    dreg = DD|SS|TT; break;
    case 0b00011000010: code = Hex_svtrunewh,  dreg = DD|SS|TT; break;
    case 0b00011000011: code = Hex_svtrunehb2, dreg = DD|SS|TT; break;
    case 0b00011000100: code = Hex_svtrunowh,  dreg = DD|SS|TT; break;
    case 0b00011000101: code = Hex_svtrunohb2, dreg = DD|SS|TT; break;
    case 0b00011000110: code = Hex_lfs,        dreg = DD|SS|TT; break;

    case 0b00011100000: code = Hex_svxaddsubh, dreg = DD|SS|TT, flags = IPO_RND_RS1_SAT; break;
    case 0b00011100010: code = Hex_svxsubaddh, dreg = DD|SS|TT, flags = IPO_RND_RS1_SAT; break;
    case 0b00011100100: code = Hex_extract,    dreg = DD|SS|TT; break;
    case 0b00011100110: code = Hex_decbin,     dreg = DD|SS|TT; break;

    case 0b00110000000: code = Hex_svasrw,     dreg = DD|SS; break;
    case 0b00110000010: code = Hex_svlsrw,     dreg = DD|SS; break;
    case 0b00110000100: code = Hex_svaslw,     dreg = DD|SS; break;
    case 0b00110000110: code = Hex_svlslw,     dreg = DD|SS; break;

    case 0b00110100000: code = Hex_svasrh,     dreg = DD|SS; break;
    case 0b00110100010: code = Hex_svlsrh,     dreg = DD|SS; break;
    case 0b00110100100: code = Hex_svaslh,     dreg = DD|SS; break;
    case 0b00110100110: code = Hex_svlslh,     dreg = DD|SS; break;

    case 0b00111100000: code = Hex_svcrotate,  dreg = DD|SS; break;
    case 0b00111100010: code = Hex_svcnegh,    dreg = DD|SS; break;

    case 0b01010000010: code = Hex_svasrw,     dreg = SS; break;

    case 0b01100000000: code = Hex_asr,        dreg = 0, flags = IPO_SAT; break;
    case 0b01100000100: code = Hex_asl,        dreg = 0, flags = IPO_SAT; break;

    case 0b01101000000: code = Hex_setbit2,    dreg = 0; break;
    case 0b01101000010: code = Hex_clrbit2,    dreg = 0; break;
    case 0b01101000100: code = Hex_togglebit,  dreg = 0; break;

    case 0b01101100000: code = Hex_cround,     dreg = 0; break;
    case 0b01101100010: code = Hex_cround,     dreg = DD|SS; break;
    case 0b01101100100: code = Hex_round2,     dreg = 0; break;
    case 0b01101100110: code = Hex_round2,     dreg = 0, flags = IPO_SAT; break;

    case 0b10000000000: code = Hex_insert,     dreg = TT; break;

    case 0b10010000000: code = Hex_extractu,   dreg = TT; break;
    case 0b10010000010: code = Hex_extract,    dreg = TT; break;

    case 0b10100000000: code = Hex_insert,     dreg = DD|SS|TT; break;

    case 0b10101000000: code = Hex_xor,        dreg = DD|SS|TT, flags = IAT_XOR; break;

    case 0b10110011111: code = Hex_svrcnegh,   dreg = DD|SS, flags = IAT_ADD; break;
    default: return 0;
    }
    op_reg( ops[0], REG_R(d5), FLG_D(dreg) );
    op_reg( ops[1], REG_R(s5), FLG_S(dreg) );
    op_reg( ops[2], REG_R(t5), FLG_T(dreg) );
    return code;
}

static uint32_t iclass_13_ALU64( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t code, s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);
    bool extended = extender != 0;

    switch( BITS(27:24) )
    {
    case 0b0000:
        if( BITS(23:21) == 0 && BIT(13) == 0 && BITS(7:5) == 0 )
        {
            // Rd32 = parity(Rss32,Rtt32)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            return Hex_parity;
        }
        break;

    case 0b0001:
        if( BITS(23:21) == 0 && BIT(13) == 0 && BIT(7) == 0 )
        {
            // Rdd32 = vmux(Pu4,Rss32,Rtt32)
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_P(BITS(6:5)) );
            op_reg( ops[2], REG_R(s5), REG_DOUBLE );
            op_reg( ops[3], REG_R(t5), REG_DOUBLE );
            return Hex_svmux;
        }
        break;

    case 0b0010:
        while( BITS(23:21) == 0 && d5 <= 3 )
        {
            // Pd4 = vcmp{b|h|w}.{eq|gt|gtu}(Rss32,Rtt32)
            static const uint32_t flg[16] = {
                SZ_W|CMP_EQ, SZ_W|CMP_GT,  SZ_W|CMP_GTU,
                SZ_H|CMP_EQ, SZ_H|CMP_GT,  SZ_H|CMP_GTU,
                SZ_B|CMP_EQ, SZ_B|CMP_GTU, 0,
                0,           SZ_B|CMP_GT,
            };
            flags = flg[ (BIT(13) << 3) | BITS(7:5) ];
            if( !flags ) break;
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            return Hex_svcmp;
        }
        if( BITS(23:21) == 0 && BIT(13) == 1 && BITS(7:6) == 0 && BITS(4:2) == 0 )
        {
            // Pd4 = [!]any8(vcmpb.eq(Rss32,Rtt32))
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            flags = (BIT(5)? IAT_NOT : 0) | CMP_EQ;
            return Hex_svcmpbeq_any;
        }
        if( BITS(23:21) == 0 && BIT(13) == 1 && BITS(7:2) == 0x18 )
        {
            // Pd4 = tlbmatch(Rss32,Rt32)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5) );
            return Hex_tlbmatch;
        }
        if( BITS(23:21) == 0 && BIT(13) == 1 && (BITS(7:2) == 0x20 || BITS(7:2) == 0x28) )
        {
            // Pd4 = boundscheck(Rs32,Rtt32) [mapped from raw]
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5) + BIT(5) );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            return Hex_boundscheck;
        }
        if( BITS(23:21) == 0b100 && BIT(13) == 0 && BITS(7:6) != 0b11 && BITS(5:0) <= 3 )
        {
            // Pd4 = cmp.{eq|gt|gtu}(Rss32,Rtt32)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            flags = BITS(7:6) << CMP_SHIFT;
            return Hex_cmp;
        }
        if( BITS(23:21) == 0b111 && BIT(13) == 0 && BIT(7) == 0 && d5 <= 3 )
        {
            // Pd4 = dfcmp.{eq|gt|ge|uo}(Rss32,Rtt32)
            static const uint32_t cmp[4] = { CMP_EQ, CMP_GT, CMP_GE, CMP_UO };
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            flags = cmp[ BITS(6:5) ];
            return Hex_dfcmp;
        }
        break;

    case 0b0011:
        if( BIT(13) != 0 ) break;
        if( BITS(23:22) == 0 )
        {
            // Rdd32 = [v]{add|sub}[ub|h|uh|w](Rss32,Rtt32)[:sat]
            static const uint16_t itypes[16] = {
                Hex_svaddub, Hex_svaddub, Hex_svaddh, Hex_svaddh, Hex_svadduh, Hex_svaddw, Hex_svaddw, Hex_add,
                Hex_svsubub, Hex_svsubub, Hex_svsubh, Hex_svsubh, Hex_svsubuh, Hex_svsubw, Hex_svsubw, Hex_sub,
            };
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            flags = (BIT(5) ^ BIT(7))? IPO_SAT : 0;
            return itypes[ (BIT(21) << 3) | BITS(7:5) ];
        }
        if( BITS(23:21) == 0b011 && BITS(7:6) == 0b11 )
        {
            // Rdd32 = add(Rs32,Rtt32) [mapped from raw]
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5) + BIT(5) );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            return Hex_add;
        }
        if( BITS(23:21) == 0b101 || BITS(23:21) == 0b110 )
        {
            // Rdd32 = [v]{max|min}[ub|h|uh|w](Rss32,Rtt32)
            static const uint16_t itypes[16] = {
                Hex_svmaxub, Hex_svmaxh, Hex_svmaxuh, Hex_svmaxw, Hex_max,     Hex_maxu,    Hex_svmaxb, Hex_svminb,
                Hex_svminub, Hex_svminh, Hex_svminuh, Hex_svminw, Hex_svminuw, Hex_svmaxuw, Hex_min,    Hex_minu,
            };
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            return itypes[ (BIT(21) << 3) | BITS(7:5) ];
        }
        if( BITS(23:21) == 0b111 && BIT(7) == 0 )
        {
            // Rdd32 = {and|or}{(Rss32,Rtt32)|(Rtt32,~Rss32)}
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            if( BIT(5) ) {
                op_reg( ops[1], REG_R(t5), REG_DOUBLE );
                op_reg( ops[2], REG_R(s5), REG_DOUBLE | REG_PRE_NEG );
            } else {
                op_reg( ops[1], REG_R(s5), REG_DOUBLE );
                op_reg( ops[2], REG_R(t5), REG_DOUBLE );
            }
            return BIT(6)? Hex_or : Hex_and;
        }
        if( BITS(23:21) == 0b111 && BITS(7:5) == 0b111 )
        {
            // Rd32 = modwrap(Rs32,Rt32)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], REG_R(t5) );
            return Hex_modwrap;
        }
        // all other code 3 instructions:
        switch( (BITS(23:21) << 3) | BITS(7:5) )
        {
        case 0b010000: code = Hex_svavg;   flags = SZ_UB; break;
        case 0b010001: code = Hex_svavg;   flags = SZ_UB | IPO_RND; break;
        case 0b010010: code = Hex_svavg;   flags = SZ_H; break;
        case 0b010011: code = Hex_svavg;   flags = SZ_H | IPO_RND; break;
        case 0b010100: code = Hex_svavg;   flags = SZ_H | IPO_CRND; break;
        case 0b010101: code = Hex_svavg;   flags = SZ_UH; break;
        case 0b010110: code = Hex_svavg;   flags = SZ_UH | IPO_RND; break;
        case 0b011000: code = Hex_svavg;   flags = SZ_W; break;
        case 0b011001: code = Hex_svavg;   flags = SZ_W | IPO_RND; break;
        case 0b011010: code = Hex_svavg;   flags = SZ_W | IPO_CRND; break;
        case 0b011011: code = Hex_svavg;   flags = SZ_UW; break;
        case 0b011100: code = Hex_svavg,   flags = SZ_UW | IPO_RND; break;
        case 0b011101: code = Hex_add;     flags = IPO_SAT; break;
        case 0b100000: code = Hex_svnavg;  flags = SZ_H; break;
        case 0b100001: code = Hex_svnavg;  flags = SZ_H | IPO_RND_SAT; break;
        case 0b100010: code = Hex_svnavg;  flags = SZ_H | IPO_CRND_SAT; break;
        case 0b100011: code = Hex_svnavg;  flags = SZ_W; break;
        case 0b100100: code = Hex_svnavg;  flags = SZ_W | IPO_RND_SAT; break;
        case 0b100110: code = Hex_svnavg;  flags = SZ_W | IPO_CRND_SAT; break;
        case 0b111100: code = Hex_xor; break;
        default: return 0;
        }
        op_reg( ops[0], REG_R(d5), REG_DOUBLE );
        op_reg( ops[1], REG_R(s5), REG_DOUBLE );
        op_reg( ops[2], REG_R(t5), REG_DOUBLE );
        return code;

    case 0b0100:
        if( BITS(23:22) == 0 && BIT(13) == 0 && BITS(7:5) == 0 )
        {
            // Rdd32 = bitsplit(Rs32,Rt32) or packhl(Rs32,Rt32):deprecated
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], REG_R(t5) );
            return BIT(21)? Hex_bitsplit : Hex_packhl;
        }
        break;

    case 0b0101:
        if( BIT(13) != 0 ) break;
        if( BITS(23:22) == 0b00 && BIT(5) == 0 )
        {
            // Rd32 = add(Rt32.l,Rs32.{l|h})[:sat]
            op_reg( ops[0], REG_R(d5) );
            if( BIT(21) ) {
                op_reg( ops[1], REG_R(s5), BIT(6)? REG_POST_HI : REG_POST_LO );
                op_reg( ops[2], REG_R(t5), REG_POST_LO );
            } else {
                op_reg( ops[1], REG_R(t5), REG_POST_LO );
                op_reg( ops[2], REG_R(s5), BIT(6)? REG_POST_HI : REG_POST_LO );
            }
            flags = BIT(7)? IPO_SAT : 0;
            return BIT(21)? Hex_sub : Hex_add;
        }
        if( BITS(23:22) == 0b01 )
        {
            // Rd32 = {add|sub}(Rt32.[l|h],Rs32.[l|h})[:sat]:<<16
            op_reg( ops[0], REG_R(d5) );
            if( BIT(21) ) {
                op_reg( ops[1], REG_R(s5), BIT(5)? REG_POST_HI : REG_POST_LO );
                op_reg( ops[2], REG_R(t5), BIT(6)? REG_POST_HI : REG_POST_LO );
            } else {
                op_reg( ops[1], REG_R(t5), BIT(6)? REG_POST_HI : REG_POST_LO );
                op_reg( ops[2], REG_R(s5), BIT(5)? REG_POST_HI : REG_POST_LO );
            }
            flags = BIT(7)? IPO_SAT_LS16 : IPO_LS16;
            return BIT(21)? Hex_sub : Hex_add;
        }
        if( BITS(23:21) == 0b100 && BITS(6:5) == 0 )
        {
            // WARNING: DEPRECATED instruction
            // Rd32 = {add|sub}(Rs32,Rt32):sat:deprecated
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], REG_R(t5) );
            flags = IPO_SAT;
            return BIT(7)? Hex_sub : Hex_add;
        }
        if( (BITS(23:21) == 0b101 || BITS(23:21) == 0b110) && BITS(6:5) == 0 )
        {
            // Rd32 = {max|min}[u](Rs32,Rt32)
            static const uint8_t itypes[4] = { Hex_max, Hex_min, Hex_maxu, Hex_minu };
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], REG_R(t5) );
            return itypes[ (BIT(7) << 1) | BIT(21) ];
        }
        if( BITS(23:21) == 0b111 && BITS(7:5) == 0 )
        {
            // Rd32 = parity(Rs32,Rt32)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], REG_R(t5) );
            return Hex_parity;
        }
        break;

    case 0b0110:
    case 0b1001:
        if( BIT(23) == 0 )
        {
            // Rd[d]32 = {s|d}fmake(#Ii)[:pos|:neg]
            bool dbl = BITS(27:23) == 0b10010;
            op_reg( ops[0], REG_R(d5), dbl? REG_DOUBLE : 0 );
            op_imm( ops[1], (BIT(21) << 9 ) | BITS(13:5) );
            flags = BIT(22)? IPO_NEG : IPO_POS;
            return dbl? Hex_dfmake : Hex_sfmake;
        }
        break;

    case 0b0111:
        if( BIT(23) == 0 )
        {
            // Rd32 = add(#Ii,mpyi(Rs32,Rt32))
            op_reg( ops[0], REG_R(d5) );
            op_imm( ops[1], EXTEND( (BITS(22:21) << 4) | (BIT(13) << 3) | BITS(7:5), 0 ), false, extended );
            op_reg( ops[2], REG_R(s5) );
            op_reg( ops[3], REG_R(t5) );
            return Hex_add_mpyi;
        }
        break;

    case 0b1000: {
            // Rd32 = add(#Ii,mpyi(Rs32,#II))
            op_reg( ops[0], REG_R(t5) );
            op_imm( ops[1], EXTEND( (BITS(22:21) << 4) | (BIT(13) << 3) | BITS(7:5), 0 ), false, extended );
            op_reg( ops[2], REG_R(s5) );
            op_imm( ops[3], (BIT(23) << 5) | BITS(4:0) );
            return Hex_add_mpyi;
        }

    case 0b1010:
        if( BIT(22) == 0 )
        {
            // Rx32 |= {and|or}(Rs32,#Ii)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], EXTEND( (SBIT(21) << 9) | BITS(13:5), 0 ), true, extended );
            flags = IAT_OR;
            return BIT(23)? Hex_or : Hex_and;
        }
        if( BITS(23:22) == 0b01 )
        {
            // Rx32 = or(Ru32,and(Rx32in,#Ii))
            op_reg( ops[0], REG_R(s5) );
            op_reg( ops[1], REG_R(d5) );
            op_reg( ops[2], REG_R(s5) );
            op_imm( ops[3], EXTEND( (SBIT(21) << 9) | BITS(13:5), 0 ), true, extended );
            return Hex_or_and;
        }
        break;

    case 0b1011: {
            // Rd32 = add(Rs32,{add(Ru32,#Ii)|sub(#Ii,Ru32)})
            op_reg( ops[0], REG_R(t5) );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], REG_R(d5) );
            op_imm( ops[3], EXTEND( (SBITS(22:21) << 4) | (BIT(13) << 3) | BITS(7:5), 0 ), true, extended );
            return BIT(23)? Hex_add_sub : Hex_add_add;
        }

    case 0b1100:
        if( BITS(23:21) <= 0b010 && BIT(13) == 0 &&
            BITS(4:3) <= 2 && BIT(2) == 0 && !(BIT(22) & BIT(12)) )
        {
            // Pd4 = vcmp%s%c(Rss32,#Ii)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], SBITS(12:5), true );
            flags = (BITS(23:21) << CMP_SHIFT) |  // CMP_EQ/CMP_GT/CMP_GTU
                    (BIT(4)? SZ_W : BIT(3)? SZ_H : SZ_B);
            return Hex_svcmp;
        }
        if( BITS(23:21) == 0b100 && BITS(13:10) == 0 && BITS(4:2) == 0b100 )
        {
            // Pd4 = dfclass(Rss32,#Ii)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_imm( ops[2], BITS(9:5) );
            return Hex_dfclass;
        }
        break;

    case 0b1101:
        if( BITS(23:21) <= 0b010 && BIT(13) == 0 &&
            BIT(4) == 0 && BIT(2) == 0 && !(BIT(22) & BIT(12)) )
        {
            // Pd4 = cmp%s%c(Rs32,#Ii)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5) );
            op_imm( ops[2], EXTEND(SBITS(12:5), 0), true, extended );
            flags = (BITS(23:21) << CMP_SHIFT) |  // CMP_EQ/CMP_GT/CMP_GTU
                    (BIT(3)? SZ_H : SZ_B);
            return Hex_cmp;
        }
        break;

    case 0b1110:
        if( BIT(0) == 0 )
        {
            // Rx32 = <op1>(#Ii,<shift>(Rx32in,#II))
            static const uint8_t itypes[8] = {
                Hex_and_asl, Hex_or_asl, Hex_add_asl, Hex_sub_asl,
                Hex_and_lsr, Hex_or_lsr, Hex_add_lsr, Hex_sub_lsr
            };
            op_reg( ops[0], REG_R(s5) );
            op_imm( ops[1], EXTEND( (BITS(23:21) << 5)| (BIT(13) << 4) | (BITS(7:5) << 1) | BIT(3), 0 ), false, extended );
            op_imm( ops[2], BITS(12:8) );
            return itypes[ (BIT(4) << 2) | BITS(2:1) ];
        }
        break;

    case 0b1111: {
            // Rd32 = add(Ru32,mpyi(#Ii,Rs32)) or add(Ru32,mpyi(Rs32,#Ii))
            op_reg( ops[0], REG_R(t5) );
            op_reg( ops[1], REG_R(d5) );
            if( BIT(23) ) {
                op_reg( ops[2], REG_R(s5) );
                op_imm( ops[3], EXTEND( (BITS(22:21) << 4) | (BIT(13) << 3) | BITS(7:5), 0 ), false, extended );
            } else {
                op_imm( ops[2], (BITS(22:21) << 6) | (BIT(13) << 5) | (BITS(7:5) << 2) );
                op_reg( ops[3], REG_R(s5) );
            }
            return Hex_add_mpyi;
        }
        break;
    }
    return 0;
}

static uint32_t iclass_14_M( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    if( BIT(13) != 0 ) return 0;

    uint32_t rs = REG_R(BITS(20:16)), rt = REG_R(BITS(12:8)), rd = REG_R(BITS(4:0));
    bool extended = extender != 0;

    // most common cases
    if( (BITS(27:21) & 0b0111010) == 0b0100000 && (BIT(27) || !BIT(7)) )
    {
        // Rd[d]32 = mpy(Rs32.{l|h},Rt32.{l|h})[:<<1][:rnd][:sat]
        static const uint16_t post[8] = {
            IPO_NONE, IPO_SAT,     IPO_RND,     IPO_RND_SAT,
            IPO_LS1,  IPO_LS1_SAT, IPO_LS1_RND, IPO_LS1_RND_SAT,
        };
        op_reg( ops[0], rd, BIT(27)? 0 : REG_DOUBLE );
        op_reg( ops[1], rs, BIT(6)? REG_POST_HI : REG_POST_LO );
        op_reg( ops[2], rt, BIT(5)? REG_POST_HI : REG_POST_LO );
        flags = post[ (BIT(23) << 2) | (BIT(21) << 1) | BIT(7) ];
        return Hex_mpy;
    }
    if( (BITS(27:21) & 0b0111010) == 0b0110000 && (BIT(27) || !BIT(7)) )
    {
        // Rx[x]32 ±= mpy(Rs32.{l|h},Rt32.{l|h})[:<<1][:sat]
        static const uint16_t post[4] = { IPO_NONE, IPO_SAT, IPO_LS1, IPO_LS1_SAT };
        op_reg( ops[0], rd, BIT(27)? 0 : REG_DOUBLE );
        op_reg( ops[1], rs, BIT(6)? REG_POST_HI : REG_POST_LO );
        op_reg( ops[2], rt, BIT(5)? REG_POST_HI : REG_POST_LO );
        flags = post[ (BIT(23) << 1) | BIT(7) ] |
                (BIT(21)? IAT_SUB : IAT_ADD);
        return Hex_mpy;
    }
    if( (BITS(27:21) & 0b0101010) == 0b0100010 && BIT(7) == 0 && (BIT(25) || !BIT(21)) )
    {
        // Rx[x]32 [±]= mpyu(Rs32.{l|h},Rt32.{l|h})[:<<1]
        op_reg( ops[0], rd, BIT(27)? 0 : REG_DOUBLE );
        op_reg( ops[1], rs, BIT(6)? REG_POST_HI : REG_POST_LO );
        op_reg( ops[2], rt, BIT(5)? REG_POST_HI : REG_POST_LO );
        flags = (BIT(23)? IPO_LS1 : 0);
        if( BIT(25) ) flags |= (BIT(21)? IAT_SUB : IAT_ADD);
        return Hex_mpyu;
    }
    // special cases
    if( (BITS(27:21) & 0b1101101) == 0b1000101 && BITS(7:5) == 0b100 )
    {
        // Rxx32 [+]= vrcmpys(Rss32,Rt32):<<1:sat
        op_reg( ops[0], rd, REG_DOUBLE );
        op_reg( ops[1], rs, REG_DOUBLE );
        op_reg( ops[2], rt + !BIT(22) ); // mapped from raw
        flags = IPO_LS1_SAT | (BIT(25)? IAT_ADD : 0);
        return Hex_svrcmpys;
    }
    if( BITS(27:21) == 0b1001101 && BITS(7:6) == 0b11 )
    {
        // Rd32 = vrcmpys(Rss32,Rt32):<<1:rnd:sat
        op_reg( ops[0], rd );
        op_reg( ops[1], rs, REG_DOUBLE );
        op_reg( ops[2], rt + !BIT(5) ); // mapped from raw
        flags = IPO_LS1_RND_SAT;
        return Hex_svrcmpys;
    }
    if( (BITS(27:21) & 0b1110011) == 0b0000000 )
    {
        // Rx32 [±]= mpyi(Rs32,#Ii)
        uint32_t imm = BITS(12:5);
        op_reg( ops[0], rd );
        op_reg( ops[1], rs );
        if( BITS(24:23) == 0b01 )
            op_imm( ops[2], -(int32_t)imm, true ); // mapped from -mpyi
        else
            op_imm( ops[2], EXTEND(imm, 0), false, extended );
        if( BIT(24) ) flags = BIT(23)? IAT_SUB : IAT_ADD;
        return Hex_mpyi;
    }
    if( (BITS(27:21) & 0b1111011) == 0b0010000 )
    {
        // Rx32 ±= add(Rs32,#Ii)
        op_reg( ops[0], rd );
        op_reg( ops[1], rs );
        op_imm( ops[2], EXTEND(SBITS(12:5), 0), true, extended );
        flags = BIT(23)? IAT_SUB : IAT_ADD;
        return Hex_add;
    }
    if( BITS(27:21) == 0b0011000 && BITS(7:5) == 0 )
    {
        // Ry32 = add(Ru32,mpyi(Ry32in,Rs32))
        op_reg( ops[0], rt );
        op_reg( ops[1], rd );
        op_reg( ops[2], rt );
        op_reg( ops[3], rs );
        return Hex_add_mpyi;
    }
    if( BITS(27:21) == 0b1010101 && BIT(7) == 0 )
    {
        // Rxx32,Pe4 = vacsh(Rss32,Rtt32)
        op_reg( ops[0], rd, REG_DOUBLE );
        op_reg( ops[1], REG_P(BITS(6:5)) );
        op_reg( ops[2], rs, REG_DOUBLE );
        op_reg( ops[3], rt, REG_DOUBLE );
        return Hex_svacsh;
    }
    if( BITS(27:21) == 0b1010111 && BIT(7) == 0 )
    {
        // Rdd32,Pe4 = vminub(Rtt32,Rss32)
        op_reg( ops[0], rd, REG_DOUBLE );
        op_reg( ops[1], REG_P(BITS(6:5)) );
        op_reg( ops[2], rs, REG_DOUBLE );
        op_reg( ops[3], rt, REG_DOUBLE );
        return Hex_svminub2d;
    }
    if( BITS(27:21) == 0b1011111 && BIT(7) == 1 )
    {
        // Rd32,Pe4 = sfrecipa(Rs32,Rt32)
        op_reg( ops[0], rd );
        op_reg( ops[1], REG_P(BITS(6:5)) );
        op_reg( ops[2], rs );
        op_reg( ops[3], rt );
        return Hex_sfrecipa;
    }
    if( BITS(27:21) == 0b1111011 && BIT(7) == 1 )
    {
        // Rx32 += sfmpy(Rs32,Rt32,Pu4):scale
        op_reg( ops[0], rd );
        op_reg( ops[1], rs );
        op_reg( ops[2], rt );
        op_reg( ops[3], REG_P(BITS(6:5)) );
        flags = IAT_ADD | IPO_SCALE;
        return Hex_sfmpy3;
    }
    // all the rest
    uint32_t tf = 0, dreg = 0, code;
    switch( (BITS(27:21) << 3) | BITS(7:5) )
    {
    case 0b0101000000: code = Hex_mpy,         dreg = DD; break;
    case 0b0101000001: code = Hex_cmpyi,       dreg = DD; break;
    case 0b0101000010: code = Hex_cmpyr,       dreg = DD; break;
    case 0b0101000101: code = Hex_svmpyh,      dreg = DD, flags = IPO_SAT; break;
    case 0b0101000110: code = Hex_cmpy,        dreg = DD, flags = IPO_SAT; break;
    case 0b0101000111: code = Hex_svmpyhsu,    dreg = DD, flags = IPO_SAT; break;
    case 0b0101010000: code = Hex_mpyu,        dreg = DD; break;
    case 0b0101010001: code = Hex_svmpybsu,    dreg = DD; break;
    case 0b0101010110: code = Hex_cmpy,        dreg = DD, flags = IPO_SAT, tf = REG_POST_CONJ; break;
    case 0b0101010111: code = Hex_pmpyw,       dreg = DD; break;
    case 0b0101100001: code = Hex_svmpybu,     dreg = DD; break;
    case 0b0101100101: code = Hex_svmpyh,      dreg = DD, flags = IPO_LS1_SAT; break;
    case 0b0101100110: code = Hex_cmpy,        dreg = DD, flags = IPO_LS1_SAT; break;
    case 0b0101100111: code = Hex_svmpyhsu,    dreg = DD, flags = IPO_LS1_SAT; break;
    case 0b0101110110: code = Hex_cmpy,        dreg = DD, flags = IPO_LS1_SAT, tf = REG_POST_CONJ; break;
    case 0b0101110111: code = Hex_svpmpyh,     dreg = DD; break;
    case 0b0111000000: code = Hex_mpy,         dreg = DD, flags = IAT_ADD; break;
    case 0b0111000001: code = Hex_cmpyi,       dreg = DD, flags = IAT_ADD; break;
    case 0b0111000010: code = Hex_cmpyr,       dreg = DD, flags = IAT_ADD; break;
    case 0b0111000101: code = Hex_svmpyh,      dreg = DD, flags = IAT_ADD | IPO_SAT; break;
    case 0b0111000110: code = Hex_cmpy,        dreg = DD, flags = IAT_ADD | IPO_SAT; break;
    case 0b0111000111: code = Hex_cmpy,        dreg = DD, flags = IAT_SUB | IPO_SAT; break;
    case 0b0111001000: code = Hex_mpy,         dreg = DD, flags = IAT_SUB; break;
    case 0b0111001001: code = Hex_svmpyh,      dreg = DD, flags = IAT_ADD; break;
    case 0b0111001111: code = Hex_pmpyw,       dreg = DD, flags = IAT_XOR; break;
    case 0b0111010000: code = Hex_mpyu,        dreg = DD, flags = IAT_ADD; break;
    case 0b0111010110: code = Hex_cmpy,        dreg = DD, flags = IAT_ADD | IPO_SAT, tf = REG_POST_CONJ; break;
    case 0b0111010111: code = Hex_cmpy,        dreg = DD, flags = IAT_SUB | IPO_SAT, tf = REG_POST_CONJ; break;
    case 0b0111011000: code = Hex_mpyu,        dreg = DD, flags = IAT_SUB; break;
    case 0b0111011101: code = Hex_svmpyhsu,    dreg = DD, flags = IAT_ADD | IPO_SAT; break;
    case 0b0111100001: code = Hex_svmpybu,     dreg = DD, flags = IAT_ADD; break;
    case 0b0111100101: code = Hex_svmpyh,      dreg = DD, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b0111100110: code = Hex_cmpy,        dreg = DD, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b0111100111: code = Hex_cmpy,        dreg = DD, flags = IAT_SUB | IPO_LS1_SAT; break;
    case 0b0111101111: code = Hex_svpmpyh,     dreg = DD, flags = IAT_XOR; break;
    case 0b0111110001: code = Hex_svmpybsu,    dreg = DD, flags = IAT_ADD; break;
    case 0b0111110110: code = Hex_cmpy,        dreg = DD, flags = IAT_ADD | IPO_LS1_SAT, tf = REG_POST_CONJ; break;
    case 0b0111110111: code = Hex_cmpy,        dreg = DD, flags = IAT_SUB | IPO_LS1_SAT, tf = REG_POST_CONJ; break;
    case 0b0111111101: code = Hex_svmpyhsu,    dreg = DD, flags = IAT_ADD | IPO_LS1_SAT; break;

    case 0b1000000000: code = Hex_svrcmpyi,    dreg = DD|SS|TT; break;
    case 0b1000000001: code = Hex_svrcmpyr,    dreg = DD|SS|TT; break;
    case 0b1000000010: code = Hex_svrmpyh,     dreg = DD|SS|TT; break;
    case 0b1000000011: code = Hex_dfadd,       dreg = DD|SS|TT; break;
    case 0b1000000100: code = Hex_svdmpy,      dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000000101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000000110: code = Hex_svmpyeh,     dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000000111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000001000: code = Hex_svabsdiff,   dreg = DD|SS|TT, flags = SZ_W; break;
    case 0b1000001010: code = Hex_svrmpywoh,   dreg = DD|SS|TT; break;
    case 0b1000001011: code = Hex_dfmax,       dreg = DD|SS|TT; break;
    case 0b1000001101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IPO_RND_SAT; break;
    case 0b1000001110: code = Hex_svcmpyr,     dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000001111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IPO_RND_SAT; break;
    case 0b1000010000: code = Hex_svrcmpyi,    dreg = DD|SS|TT, tf = REG_POST_CONJ; break;
    case 0b1000010001: code = Hex_svraddub,    dreg = DD|SS|TT; break;
    case 0b1000010010: code = Hex_svrsadub,    dreg = DD|SS|TT; break;
    case 0b1000010011: code = Hex_dfmpyfix,    dreg = DD|SS|TT; break;
    case 0b1000010100: code = Hex_svrmpyweh,   dreg = DD|SS|TT; break;
    case 0b1000010101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000010110: code = Hex_svcmpyi,     dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000010111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000011000: code = Hex_svabsdiff,   dreg = DD|SS|TT, flags = SZ_H; break;
    case 0b1000011001: code = Hex_svrcmpyr,    dreg = DD|SS|TT, tf = REG_POST_CONJ; break;
    case 0b1000011010: code = Hex_cmpyiw,      dreg = DD|SS|TT; break;
    case 0b1000011101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IPO_RND_SAT; break;
    case 0b1000011111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IPO_RND_SAT; break;
    case 0b1000100001: code = Hex_svrmpybu,    dreg = DD|SS|TT; break;
    case 0b1000100010: code = Hex_cmpyrw,      dreg = DD|SS|TT; break;
    case 0b1000100011: code = Hex_dfsub,       dreg = DD|SS|TT; break;
    case 0b1000100100: code = Hex_svdmpy,      dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000100101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000100110: code = Hex_svmpyeh,     dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000100111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000101000: code = Hex_svabsdiff,   dreg = DD|SS|TT, flags = SZ_UB; break;
    case 0b1000101001: code = Hex_svdmpybsu,   dreg = DD|SS|TT, flags = IPO_SAT; break;
    case 0b1000101010: code = Hex_svrmpywoh,   dreg = DD|SS|TT, flags = IPO_LS1; break;
    case 0b1000101011: code = Hex_dfmpyll,     dreg = DD|SS|TT; break;
    case 0b1000101101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IPO_LS1_RND_SAT; break;
    case 0b1000101110: code = Hex_svcmpyr,     dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000101111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IPO_LS1_RND_SAT; break;
    case 0b1000110001: code = Hex_svrmpybsu,   dreg = DD|SS|TT; break;
    case 0b1000110010: code = Hex_cmpyrw,      dreg = DD|SS|TT, tf = REG_POST_CONJ; break;
    case 0b1000110011: code = Hex_dfmin,       dreg = DD|SS|TT; break;
    case 0b1000110100: code = Hex_svrmpyweh,   dreg = DD|SS|TT, flags = IPO_LS1; break;
    case 0b1000110101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000110110: code = Hex_svcmpyi,     dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000110111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1000111000: code = Hex_svabsdiff,   dreg = DD|SS|TT, flags = SZ_B; break;
    case 0b1000111010: code = Hex_cmpyiw,      dreg = DD|SS|TT, tf = REG_POST_CONJ; break;
    case 0b1000111101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IPO_LS1_RND_SAT; break;
    case 0b1000111111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IPO_LS1_RND_SAT; break;

    case 0b1001000000: code = Hex_svdmpy,      dreg = SS|TT, flags = IPO_RND_SAT; break;
    case 0b1001000001: code = Hex_svradduh,    dreg = SS|TT; break;
    case 0b1001000100: code = Hex_cmpyiw,      dreg = SS|TT, flags = IPO_LS1_SAT, tf = REG_POST_CONJ; break;
    case 0b1001001000: code = Hex_cmpyiw,      dreg = SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1001001111: code = Hex_svraddh,     dreg = SS|TT; break;
    case 0b1001010000: code = Hex_cmpyrw,      dreg = SS|TT, flags = IPO_LS1_SAT; break;
    case 0b1001011000: code = Hex_cmpyrw,      dreg = SS|TT, flags = IPO_LS1_SAT, tf = REG_POST_CONJ; break;
    case 0b1001100000: code = Hex_svdmpy,      dreg = SS|TT, flags = IPO_LS1_RND_SAT; break;
    case 0b1001100100: code = Hex_cmpyiw,      dreg = SS|TT, flags = IPO_LS1_RND_SAT, tf = REG_POST_CONJ; break;
    case 0b1001101000: code = Hex_cmpyiw,      dreg = SS|TT, flags = IPO_LS1_RND_SAT; break;
    case 0b1001110000: code = Hex_cmpyrw,      dreg = SS|TT, flags = IPO_LS1_RND_SAT; break;
    case 0b1001111000: code = Hex_cmpyrw,      dreg = SS|TT, flags = IPO_LS1_RND_SAT, tf = REG_POST_CONJ; break;

    case 0b1010000000: code = Hex_svrcmpyi,    dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010000001: code = Hex_svrcmpyr,    dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010000010: code = Hex_svrmpyh,     dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010000011: code = Hex_dfmpylh,     dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010000100: code = Hex_svdmpy,      dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010000101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010000110: code = Hex_svmpyeh,     dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010000111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010001001: code = Hex_svdmpybsu,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010001010: code = Hex_svmpyeh,     dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010001100: code = Hex_svcmpyr,     dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010001101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_RND_SAT; break;
    case 0b1010001110: code = Hex_svrmpyweh,   dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010001111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_RND_SAT; break;
    case 0b1010010000: code = Hex_svrcmpyi,    dreg = DD|SS|TT, flags = IAT_ADD, tf = REG_POST_CONJ; break;
    case 0b1010010001: code = Hex_svraddub,    dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010010010: code = Hex_svrsadub,    dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010010100: code = Hex_svcmpyi,     dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010010101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010010110: code = Hex_cmpyiw,      dreg = DD|SS|TT, flags = IAT_ADD, tf = REG_POST_CONJ; break;
    case 0b1010010111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_SAT; break;
    case 0b1010011001: code = Hex_svrcmpyr,    dreg = DD|SS|TT, flags = IAT_ADD, tf = REG_POST_CONJ; break;
    case 0b1010011010: code = Hex_cmpyiw,      dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010011101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_RND_SAT; break;
    case 0b1010011110: code = Hex_svrmpywoh,   dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010011111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_RND_SAT; break;
    case 0b1010100001: code = Hex_svrmpybu,    dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010100010: code = Hex_cmpyrw,      dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010100011: code = Hex_dfmpyhh,     dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010100100: code = Hex_svdmpy,      dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1010100101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1010100110: code = Hex_svmpyeh,     dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1010100111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1010101101: code = Hex_svmpyweh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_RND_SAT; break;
    case 0b1010101110: code = Hex_svrmpyweh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1; break;
    case 0b1010101111: code = Hex_svmpywoh,    dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_RND_SAT; break;
    case 0b1010110001: code = Hex_svrmpybsu,   dreg = DD|SS|TT, flags = IAT_ADD; break;
    case 0b1010110010: code = Hex_cmpyrw,      dreg = DD|SS|TT, flags = IAT_ADD, tf = REG_POST_CONJ; break;
    case 0b1010110101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1010110111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1010111101: code = Hex_svmpyweuh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_RND_SAT; break;
    case 0b1010111110: code = Hex_svrmpywoh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1; break;
    case 0b1010111111: code = Hex_svmpywouh,   dreg = DD|SS|TT, flags = IAT_ADD | IPO_LS1_RND_SAT; break;

    case 0b1011000000: code = Hex_sfadd; break;
    case 0b1011000001: code = Hex_sfsub; break;
    case 0b1011010000: code = Hex_sfmpy; break;
    case 0b1011100000: code = Hex_sfmax; break;
    case 0b1011100001: code = Hex_sfmin; break;
    case 0b1011110000: code = Hex_sffixupn; break;
    case 0b1011110001: code = Hex_sffixupd; break;
    case 0b1101000000: code = Hex_mpyi; break;
    case 0b1101000001: code = Hex_mpy; break;
    case 0b1101001001: code = Hex_mpy,    flags = IPO_RND; break;
    case 0b1101001110: code = Hex_cmpy,   flags = IPO_RND_SAT; break;
    case 0b1101001111: code = Hex_svmpyh, flags = IPO_RND_SAT; break;
    case 0b1101010001: code = Hex_mpyu; break;
    case 0b1101011001: code = Hex_mpysu; break;
    case 0b1101011110: code = Hex_cmpy,   flags = IPO_RND_SAT, tf = REG_POST_CONJ; break;
    case 0b1101101000: code = Hex_mpy,    flags = IPO_LS1_SAT, tf = REG_POST_HI; break;
    case 0b1101101001: code = Hex_mpy,    flags = IPO_LS1_SAT, tf = REG_POST_LO; break;
    case 0b1101101010: code = Hex_mpy,    flags = IPO_LS1; break;
    case 0b1101101100: code = Hex_mpy,    flags = IPO_LS1_RND_SAT, tf = REG_POST_HI; break;
    case 0b1101101110: code = Hex_cmpy,   flags = IPO_LS1_RND_SAT; break;
    case 0b1101101111: code = Hex_svmpyh, flags = IPO_LS1_RND_SAT; break;
    case 0b1101111000: code = Hex_mpy,    flags = IPO_LS1_SAT; break;
    case 0b1101111100: code = Hex_mpy,    flags = IPO_LS1_RND_SAT, tf = REG_POST_LO; break;
    case 0b1101111110: code = Hex_cmpy,   flags = IPO_LS1_RND_SAT, tf = REG_POST_CONJ; break;
    case 0b1111000000: code = Hex_mpyi,   flags = IAT_ADD; break;
    case 0b1111000001: code = Hex_add,    flags = IAT_ADD; break;
    case 0b1111000011: code = Hex_sub,    flags = IAT_ADD; break;
    case 0b1111000100: code = Hex_sfmpy,  flags = IAT_ADD; break;
    case 0b1111000101: code = Hex_sfmpy,  flags = IAT_SUB; break;
    case 0b1111000110: code = Hex_sfmpy,  flags = IAT_ADD | IPO_LIB; break;
    case 0b1111000111: code = Hex_sfmpy,  flags = IAT_SUB | IPO_LIB; break;
    case 0b1111001000: code = Hex_and,    flags = IAT_OR,  tf = REG_PRE_NEG; break;
    case 0b1111001001: code = Hex_and,    flags = IAT_AND, tf = REG_PRE_NEG; break;
    case 0b1111001010: code = Hex_and,    flags = IAT_XOR, tf = REG_PRE_NEG; break;
    case 0b1111010000: code = Hex_and,    flags = IAT_AND; break;
    case 0b1111010001: code = Hex_or,     flags = IAT_AND; break;
    case 0b1111010010: code = Hex_xor,    flags = IAT_AND; break;
    case 0b1111010011: code = Hex_and,    flags = IAT_OR; break;
    case 0b1111011000: code = Hex_mpy,    flags = IAT_ADD | IPO_LS1_SAT; break;
    case 0b1111011001: code = Hex_mpy,    flags = IAT_SUB | IPO_LS1_SAT; break;
    case 0b1111100000: code = Hex_mpyi,   flags = IAT_SUB; break;
    case 0b1111100001: code = Hex_add,    flags = IAT_SUB; break;
    case 0b1111100011: code = Hex_xor,    flags = IAT_XOR; break;
    case 0b1111110000: code = Hex_or,     flags = IAT_OR; break;
    case 0b1111110001: code = Hex_xor,    flags = IAT_OR; break;
    case 0b1111110010: code = Hex_and,    flags = IAT_XOR; break;
    case 0b1111110011: code = Hex_or,     flags = IAT_XOR; break;

    default: return 0;
    }
    op_reg( ops[0], rd, FLG_D(dreg) );
    op_reg( ops[1], rs, FLG_S(dreg) );
    op_reg( ops[2], rt, FLG_T(dreg) | tf );
    return code;
}

static uint32_t iclass_15_ALU3op( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);
    uint32_t code = BITS(27:21);

    if( BITS(27:24) == 0b0001 && BIT(13) == 0 && BITS(7:5) == 0 )
    {
        // Rd32 = <logic>(Rt32,[~]Rs32)
        static const uint8_t itypes[8] = { Hex_and, Hex_or, 0, Hex_xor, Hex_and, Hex_or };
        op_reg( ops[0], REG_R(d5) );
        if( BIT(23) ) SWAP( s5, t5 );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5), BIT(23)? REG_PRE_NEG : 0 );
        return itypes[ BITS(23:21) ];
    }

    if( BITS(27:23) == 0b00100 && BITS(22:21) != 1 && BIT(13) == 0 && BITS(7:5) == 0 && BITS(3:2) == 0 )
    {
        // Pd4 = [!]cmp%c(Rs32,Rt32)
        static const uint32_t cmp[4] = { CMP_EQ, 0, CMP_GT, CMP_GTU };
        flags = cmp[BITS(22:21)] | (BIT(4)? IAT_NOT : 0);
        op_reg( ops[0], REG_P(BITS(1:0)) );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        return Hex_cmp;
    }
    if( BITS(27:23) == 0b00111 && BIT(13) == 0 && BITS(7:5) == 0 )
    {
        // Rd32 = combine(Rt32.{l|h},Rs32.{l|h})
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_R(t5), BIT(22)? REG_POST_LO : REG_POST_HI );
        op_reg( ops[2], REG_R(s5), BIT(21)? REG_POST_LO : REG_POST_HI );
        return Hex_combine;
    }
    if( BITS(27:21) == 0b0100000 && BIT(13) == 0 && BIT(7) == 0 )
    {
        // Rd32 = mux(Pu4,Rs32,Rt32)
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_P(BITS(6:5)) );
        op_reg( ops[2], REG_R(s5) );
        op_reg( ops[3], REG_R(t5) );
        return Hex_mux;
    }
    while( BIT(27) == 1 && BITS(24:23) == 0b10 )
    {
        // if ([!]Pu[.new]) Rd32 = <op>(Rs32,Rt32)
        static const uint8_t itypes[16] = { Hex_and, Hex_or, 0, Hex_xor, Hex_add, Hex_sub, 0, 0, Hex_combine };
        uint32_t itype = itypes[ (BITS(26:25) << 2) | BITS(22:21) ];
        if( itype == 0 ) break;
        op_reg( ops[PRED_A], REG_P(BITS(6:5)),
                (BIT(7)? REG_PRE_NOT : 0) |
                (BIT(13)? REG_POST_NEW : 0) );
        op_reg( ops[0], REG_R(d5), itype == Hex_combine? REG_DOUBLE : 0 );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        flags = PRED_REG;
        return itype;
    }
    if( 24 <= code && code <= 59 && BIT(13) == 0 && BITS(7:5) == 0 )
    {
        // Rd[d]32 = <op>(Rs32,Rt32)
        switch( code )
        {
        case 24: code = Hex_add;     break;
        case 25: code = Hex_sub;     break;
        case 26: code = Hex_cmp;     break;
        case 27: code = Hex_cmp;     flags = IAT_NOT; break;
        case 40: code = Hex_combine; break;
        case 44: code = Hex_packhl;  break;
        case 48: code = Hex_svaddh;  break;
        case 49: code = Hex_svaddh;  flags = IPO_SAT; break;
        case 50: code = Hex_add;     flags = IPO_SAT; break;
        case 51: code = Hex_svadduh; flags = IPO_SAT; break;
        case 52: code = Hex_svsubh;  break;
        case 53: code = Hex_svsubh;  flags = IPO_SAT; break;
        case 54: code = Hex_sub;     flags = IPO_SAT; break;
        case 55: code = Hex_svsubuh; flags = IPO_SAT; break;
        case 56: code = Hex_svavg;   flags = SZ_H; break;
        case 57: code = Hex_svavg;   flags = SZ_H | IPO_RND; break;
        case 59: code = Hex_svnavg;  flags = SZ_H; break;
        default: return 0;
        }
        op_reg( ops[0], REG_R(d5), code == Hex_combine || code == Hex_packhl? REG_DOUBLE : 0 );
        op_reg( ops[1], REG_R(s5) );
        op_reg( ops[2], REG_R(t5) );
        return code;
    }
    return 0;
}

//
// system instructions parsing
//

static uint32_t iclass_5_SYS( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);

    if( BITS(27:24) == 0b0100 && BIT(21) == 0 && BIT(13) == 0 && BITS(7:5) == 0 && BITS(1:0) == 0 )
    {
        // {trap0|trap1|pause}(#Ii)
        const uint8_t itypes[4] = { Hex_trap0, Hex_pause, Hex_trap1_2, 0 };
        uint32_t code = BITS(23:22), imm = (BITS(12:8) << 3) | BITS(4:2);
        if( code == 2 ) {
            op_reg( ops[0], REG_R(s5) );
            op_imm( ops[1], imm );
        }
        else {
            if( s5 ) return 0;
            op_imm( ops[0], imm );
        }
        return itypes[ code ];
    }
    if( BITS(27:23) == 0b01011 && BIT(21) == 1 && BITS(13:5) == 0 )
    {
        // Rd=ic{data|tag}r(Rs)
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_R(s5) );
        return BIT(22)? Hex_ictagr : Hex_icdatar;
    }
    if( BITS(27:21) == 0b0101110 && BITS(7:5) == 0 )
    {
        // ic{data|tag}w(Rs,Rt)
        op_reg( ops[0], REG_R(s5) );
        op_reg( ops[1], REG_R(t5) );
        return BIT(13)? Hex_icdataw : Hex_ictagw;
    }
    if( BITS(27:21) == 0b0110110 && BIT(13) == 0 && BITS(10:0) == 0 )
    {
        // icinv{a|idx}(Rs32), ickill
        const uint8_t itypes[4] = { Hex_icinva, Hex_icinvidx, Hex_ickill, 0 };
        if( !BIT(12) ) op_reg( ops[0], REG_R(s5) );
        else if( s5 ) return 0;
        return itypes[ BITS(12:11) ];
    }
    if( BITS(27:16) == 0b011111000000 && BITS(13:0) == 2 )
    {
        // isync
        return Hex_isync;
    }
    if( BITS(27:16) == 0b011111100000 && BIT(13) == 0 && BITS(11:0) == 0 )
    {
        // {unpause|rte}
        return BIT(12)? Hex_unpause : Hex_rte;
    }
    return 0;
}

static uint32_t iclass_6_SYS( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);

    switch( BITS(27:24) )
    {
    case 0b0100:
        if( BITS(23:21) == 0b000 && BITS(13:5) <= 3 && d5 == 0 )
        {
            // swi/cswi/iassignw/ciad(Rs)
            static const uint8_t itypes[] = { Hex_swi, Hex_cswi, Hex_iassignw, Hex_ciad };
            op_reg( ops[0], REG_R(s5) );
            return itypes[ BITS(13:5) ];
        }
        if( BITS(23:21) == 0b010 && BITS(13:5) <= 1 && d5 == 0 )
        {
            // wait/resume(Rs32)
            op_reg( ops[0], REG_R(s5) );
            return BIT(5)? Hex_resume : Hex_wait;
        }
        if( BITS(23:21) == 0b011 && BITS(13:5) <= 2 && d5 == 0 )
        {
            // stop/start/nmi(Rs)
            static const uint8_t itypes[] = { Hex_stop, Hex_start, Hex_nmi };
            op_reg( ops[0], REG_R(s5) );
            return itypes[ BITS(13:5) ];
        }
        if( BITS(23:21) == 0b100 && BITS(13:10) == 0 && BITS(8:5) <= 1 && d5 == 0 )
        {
            // set{prio|imask}(Pt,Rs)
            op_reg( ops[0], REG_P(BITS(9:8)) );
            op_reg( ops[1], REG_R(s5) );
            return BIT(5)? Hex_setprio : Hex_setimask;
        }
        if( BITS(23:21) == 0b100 && BITS(13:0) == 0b00000001100000 )
        {
            // siad(Rs)
            op_reg( ops[0], REG_R(s5) );
            return Hex_siad;
        }
        break;

    case 0b0101:
        if( BITS(23:22) == 0 && BITS(13:0) == 0 )
        {
            // crswap(Rx,sgp{0|1})
            op_reg( ops[0], REG_R(s5) );
            op_reg( ops[1], REG_S(BIT(21)) );
            return Hex_crswap;
        }
        break;

    case 0b0110:
        if( BITS(23:21) == 0b000 && BITS(13:5) == 0 )
        {
            // Rd=getimask(Rs)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            return Hex_getimask;
        }
        if( BITS(23:21) == 0b011 && BITS(13:5) == 0 )
        {
            // Rd=iassignr(Rs)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            return Hex_iassignr;
        }
        break;

    case 0b0111:
        if( BITS(23:21) == 0 && BITS(13:7) == 0 )
        {
            // Sd=Rs
            op_reg( ops[0], REG_S(BITS(6:0)) );
            op_reg( ops[1], REG_R(s5) );
            return Hex_mov;
        }
        break;

    case 0b1100:
        if( BITS(23:21) == 0b000 && BIT(13) == 0 && BITS(7:0) == 0 )
        {
            // tlbw(Rss,Rt)
            op_reg( ops[0], REG_R(s5), REG_DOUBLE );
            op_reg( ops[1], REG_R(t5) );
            return Hex_tlbw;
        }
        if( BITS(23:16) == 0b00100000 && BITS(13:5) <= 4 && d5 == 0 )
        {
            // brkpt/tlb[un]lock/k0[un]lock
            static const uint8_t itypes[] = { Hex_brkpt, Hex_tlblock, Hex_tlbunlock, Hex_k0lock, Hex_k0unlock };
            return itypes[ BITS(13:5) ];
        }
        if( BITS(23:21) == 0b010 && BITS(13:5) == 0 )
        {
            // Rdd=tlbr(Rs)
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5) );
            return Hex_tlbr;
        }
        if( BITS(23:21) == 0b100 && BITS(13:5) == 0 )
        {
            // Rd=tlbp(Rs)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            return Hex_tlbp;
        }
        if( BITS(23:21) == 0b101 && BITS(13:0) == 0 )
        {
            // tlbinvasid(Rs)
            op_reg( ops[0], REG_R(s5) );
            return Hex_tlbinvasid;
        }
        if( BITS(23:21) == 0b110 && BIT(13) == 0 && BITS(7:5) == 0 )
        {
            // Rd=ctlbw(Rss,Rt)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            op_reg( ops[2], REG_R(t5) );
            return Hex_ctlbw;
        }
        if( BITS(23:21) == 0b111 && BITS(13:5) == 0 )
        {
            // Rd=tlboc(Rss)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            return Hex_tlboc;
        }
        break;

    case 0b1101:
        if( BITS(23:21) == 0b000 && BITS(13:7) == 0 )
        {
            // Sdd=Rss
            op_reg( ops[0], REG_S(BITS(6:0)), REG_DOUBLE );
            op_reg( ops[1], REG_R(s5), REG_DOUBLE );
            return Hex_mov;
        }
        if( BITS(23:21) == 0b100 && BITS(13:0) == 0 )
        {
            // crswap(Rxx,sgp1:0);
            op_reg( ops[0], REG_R(s5), REG_DOUBLE );
            op_reg( ops[1], REG_S0, REG_DOUBLE );
            return Hex_crswap;
        }
        break;

    case 0b1110:
        if( BIT(23) == 1 && BITS(13:5) == 0 )
        {
            // Rd=Ss
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_S(BITS(22:16)) );
            return Hex_mov;
        }
        break;

    case 0b1111:
        if( BIT(23) == 0 && BITS(13:5) == 0 )
        {
            // Rdd=Sss
            op_reg( ops[0], REG_R(d5), REG_DOUBLE );
            op_reg( ops[1], REG_S(BITS(22:16)), REG_DOUBLE );
            return Hex_mov;
        }
        break;
    }
    return 0;
}

static uint32_t iclass_10_SYS( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);

    switch( BITS(27:24) )
    {
    case 0b0000:
        if( BITS(13:0) == 0 )
        {
            // dc{clean|inv|cleaninv|zero}a(Rs32)
            static const uint8_t itypes[8] = { Hex_dccleana, Hex_dcinva, Hex_dccleaninva, 0, 0, 0, Hex_dczeroa, };
            op_reg( ops[0], REG_R(s5) );
            return itypes[ BITS(23:21) ];
        }
        if( BITS(23:21) == 0b111 && BITS(13:2) == 0b100000000000 )
        {
            // Pd=l2locka(Rs)
            op_reg( ops[0], REG_P(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5) );
            return Hex_l2locka;
        }
        break;

    case 0b0010:
        if( BITS(23:16) == 0 && BITS(13:0) == 0 )
        {
            // dckill
            return Hex_dckill;
        }
        if( BIT(23) == 0 && BITS(13:0) == 0 )
        {
            // dc[clean][inv]idx(Rs)
            static const uint8_t itypes[4] = { 0 /*dckill*/, Hex_dccleanidx, Hex_dcinvidx, Hex_dccleaninvidx };
            op_reg( ops[0], REG_R(s5) );
            return itypes[ BITS(22:21) ];
        }
        break;

    case 0b0100:
        if( BIT(23) == 0 && BIT(21) == 0 && BIT(13) == 0 && BITS(7:0) == 0 )
        {
            // {l2|dc}tagw(Rs,Rt)
            op_reg( ops[0], REG_R(s5) );
            op_reg( ops[1], REG_R(t5) );
            return BIT(22)? Hex_l2tagw : Hex_dctagw;
        }
        if( BIT(23) == 0 && BIT(21) == 1 && BITS(13:5) == 0 )
        {
            // Rd={l2|dc}tagr(Rs)
            op_reg( ops[0], REG_R(d5) );
            op_reg( ops[1], REG_R(s5) );
            return BIT(22)? Hex_l2tagr : Hex_dctagr;
        }
        break;

    case 0b0110:
        if( BITS(22:21) == 0 && BIT(13) == 0 && BITS(7:0) == 0 )
        {
            // l2fetch(Rs32,Rt[t]32)
            op_reg( ops[0], REG_R(s5) );
            op_reg( ops[1], REG_R(t5), BIT(23)? REG_DOUBLE : 0 );
            return Hex_l2fetch;
        }
        if( BIT(23) == 0 && BITS(13:0) == 0 )
        {
            // l2cleanidx(Rs) or l2unlocka(Rs)
            static const uint8_t itypes[4] = { 0 /*l2fetch*/, Hex_l2cleanidx, Hex_l2invidx, Hex_l2unlocka };
            op_reg( ops[0], REG_R(s5) );
            return itypes[ BITS(22:21) ];
        }
        if( BIT(23) == 1 && s5 == 0 && BIT(13) == 0 && BITS(7:0) == 0 )
        {
            // l2gclean[inv](Rtt)
            static const uint8_t itypes[4] = { 0, Hex_l2gclean1, Hex_l2gcleaninv1, 0 };
            op_reg( ops[0], REG_R(t5), REG_DOUBLE );
            return itypes[ BITS(22:21) ];
        }
        break;

    case 0b1000:
        if( BIT(23) == 0 && BITS(21:16) == 0 && BITS(13:0) == 0 )
        {
            // barrier|syncht
            return BIT(22)? Hex_syncht : Hex_barrier;
        }
        if( BITS(23:16) == 0b00100000 && BIT(13) == 0 && BITS(10:0) == 0 )
        {
            // l2{kill|gunlock|gclean[inv]}
            static const uint8_t itypes[4] = { Hex_l2kill, Hex_l2gunlock, Hex_l2gclean, Hex_l2gcleaninv };
            return itypes[ BITS(12:11) ];
        }
        if( BITS(23:21) == 0b011 && BITS(13:0) == 0 )
        {
            // l2cleaninvidx(Rs)
            op_reg( ops[0], REG_R(s5) );
            return Hex_l2cleaninvidx;
        }
        break;
    }
    return 0;
}

//
// HVX instructions parsing
//

static uint32_t iclass_1_HVX( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    if( BIT(27) == 0 ) return 0;

    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0);
    uint32_t v5 = BITS(23:19), t3 = BITS(18:16), code, f = 0;

    switch( BITS(26:24) )
    {
    case 0b000:
        // miscellaneous 3-argument ops
        switch( (BITS(7:5) << 1) | BIT(13) )
        {
        case 0b0000: code = Hex_vasr3,  f = RP( B, H, H),     flags = IPO_SAT; break;
        case 0b0010: code = Hex_vasr3,  f = RP(UH,UW,UW),     flags = IPO_RND_SAT; break;
        case 0b0100: code = Hex_vasr3,  f = RP(UH, W, W),     flags = IPO_RND_SAT; break;
        case 0b0110: code = Hex_vlut32, f = RP( B, B, B),     flags = IPO_NM; break;
        case 0b1000: code = Hex_vlut16, f = RP( H, B, H) |DD, flags = IPO_NM; break;
        case 0b1001: code = Hex_vasr3,  f = RP(UH,UW,UW),     flags = IPO_SAT; break;
        case 0b1011: code = Hex_vasr3,  f = RP(UB,UH,UH),     flags = IPO_SAT; break;
        case 0b1110: code = Hex_vasr3,  f = RP(UB,UH,UH),     flags = IPO_RND_SAT; break;
        default: return 0;
        }
        op_reg( ops[0], REG_V(d5), FLG_D(f) );
        op_reg( ops[1], REG_V(u5), FLG_S(f)  );
        op_reg( ops[2], REG_V(v5), FLG_T(f)  );
        op_reg( ops[3], REG_R(t3) );
        return code;

    case 0b001:
        if( BITS(23:21) == 0b001 && BITS(7:5) == 0b001 )
        {
            // Vx32.w [+]= vdmpy(Vuu32.h,Rt32.uh,#1):sat
            op_reg( ops[0], REG_V(d5), REG_POST_W );
            op_reg( ops[1], REG_V(u5), REG_DOUBLE | REG_POST_H );
            op_reg( ops[2], REG_R(s5), REG_POST_UH );
            op_imm( ops[3], 1 );
            flags = IPO_SAT | (BIT(13)? IAT_ADD : 0);
            return Hex_vdmpy3;
        }
        if( BITS(23:21) == 0b010 && BIT(7) == 1 )
        {
            // Vdd32.w [+]= vrmpy(Vuu32.ub,Rt32.b,#Ii) or
            // Vxx32.uw [+]= vrsad(Vuu32.ub,Rt32.ub,#Ii)
            op_reg( ops[0], REG_V(d5), REG_DOUBLE | (BIT(6)? REG_POST_UW : REG_POST_W) );
            op_reg( ops[1], REG_V(u5), REG_DOUBLE | REG_POST_UB );
            op_reg( ops[2], REG_R(s5), BIT(6)? REG_POST_UB : REG_POST_B );
            op_imm( ops[3], BIT(5) );
            if( BIT(13) ) flags = IAT_ADD;
            return BIT(6)? Hex_vrsad : Hex_vrmpy3;
        }
        if( (BITS(23:21) == 0b011 || BITS(23:21) == 0b101) &&
            (BIT(13) ^ BIT(22)) == 0 && BITS(12:11) == 0 && BITS(7:5) == BITS(23:21) )
        {
            // Vx32 [|]= vand([!]Qu4,Rt32)
            op_reg( ops[0], REG_V(d5) );
            op_reg( ops[1], REG_Q(BITS(9:8)), BIT(10)? REG_PRE_NOT : 0 );
            op_reg( ops[2], REG_R(s5) );
            if( BIT(13) ) flags = IAT_OR;
            return Hex_vand;
        }
        if( (BITS(23:21) == 0b011 || BITS(23:21) == 0b101) &&
            (BIT(13) ^ BIT(22)) == 0 && BITS(7:6) == 0b11 )
        {
            // Vxx32.uw [+]= vrmpy(Vuu32.ub,Rt32.ub,#Ii)
            op_reg( ops[0], REG_V(d5), REG_DOUBLE | REG_POST_UW );
            op_reg( ops[1], REG_V(u5), REG_DOUBLE | REG_POST_UB );
            op_reg( ops[2], REG_R(s5), REG_POST_UB );
            op_imm( ops[3], BIT(5) );
            if( BIT(13) ) flags = IAT_ADD;
            return Hex_vrmpy3;
        }
        if( (BITS(23:21) == 0b011 && BIT(13) == 1 && BITS(7:2) == 0b100000) ||
            (BITS(23:21) == 0b101 && BIT(13) == 0 && BITS(7:2) == 0b010010) )
        {
            // Qx4 [|]= vand(Vu32,Rt32)
            op_reg( ops[0], REG_Q(BITS(1:0)) );
            op_reg( ops[1], REG_V(u5) );
            op_reg( ops[2], REG_R(s5) );
            if( BIT(13) ) flags = IAT_OR;
            return Hex_vand;
        }
        if( BITS(23:21) == 0b101 && BITS(13:4) == 0b0000000100 && BIT(2) == 1 )
        {
            // Qd4 = vsetq[2](Rt32)
            op_reg( ops[0], REG_Q(BITS(1:0)) );
            op_reg( ops[1], REG_R(s5) );
            return BIT(3)? Hex_vsetq2 : Hex_vsetq;
        }
        if( BITS(23:21) == 0b101 && BITS(12:5) == 0b00000001 )
        {
            // Vd32 = vsplat(Rt32) or Vx32.w = vinsert(Rt32)
            op_reg( ops[0], REG_V(d5), BIT(13)? REG_POST_W : 0 );
            op_reg( ops[1], REG_R(s5) );
            return BIT(13)? Hex_vinsert : Hex_vsplat;
        }
        if( BITS(23:21) == 0b110 && BITS(13:7) == 0 && (BIT(6) ^ BIT(5)) == 1 )
        {
            // Vd32.{b|h} = vsplat(Rt32)
            op_reg( ops[0], REG_V(d5), BIT(6)? REG_POST_B : REG_POST_H );
            op_reg( ops[1], REG_R(s5) );
            return Hex_vsplat;
        }
        if( BITS(23:21) == 0b111 && BIT(13) == 1 && (BITS(7:5) == 1 || BITS(7:5) == 2) )
        {
            // v{shuff|deal}(Vy32,Vx32,Rt32)
            op_reg( ops[0], REG_V(u5) );
            op_reg( ops[1], REG_V(d5) );
            op_reg( ops[2], REG_R(s5) );
            return BIT(6)? Hex_vdeal3 : Hex_vshuff3;
        }
        // all other instructions using Rt32
        switch( (BITS(23:21) << 4) | (BIT(13) << 3) | BITS(7:5) )
        {
        case 0b0000000: code = Hex_vtmpy, f = RP( H, B, B) | DD|SS; break;
        case 0b0000001: code = Hex_vtmpy, f = RP( H,UB, B) | DD|SS; break;
        case 0b0000010: code = Hex_vdmpy, f = RP( W, H, B); break;
        case 0b0000011: code = Hex_vrmpy, f = RP(UW,UB,UB); break;
        case 0b0000100: code = Hex_vrmpy, f = RP( W,UB, B); break;
        case 0b0000101: code = Hex_vdsad, f = RP(UW,UH,UH) | DD|SS; break;
        case 0b0000110: code = Hex_vdmpy, f = RP( H,UB, B); break;
        case 0b0000111: code = Hex_vdmpy, f = RP( H,UB, B) | DD|SS; break;
        case 0b0001000: code = Hex_vtmpy, f = RP( H, B, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0001001: code = Hex_vtmpy, f = RP( H,UB, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0001010: code = Hex_vtmpy, f = RP( W, H, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0001011: code = Hex_vdmpy, f = RP( W, H, B),         flags = IAT_ADD; break;
        case 0b0001100: code = Hex_vrmpy, f = RP(UW,UB,UB),         flags = IAT_ADD; break;
        case 0b0001101: code = Hex_vrmpy, f = RP( W,UB, B),         flags = IAT_ADD; break;
        case 0b0001110: code = Hex_vdmpy, f = RP( H,UB, B),         flags = IAT_ADD; break;
        case 0b0001111: code = Hex_vdmpy, f = RP( H,UB, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0010000: code = Hex_vdmpy, f = RP( W, H,UH),         flags = IPO_SAT; break;
        case 0b0010010: code = Hex_vdmpy, f = RP( W, H, H),         flags = IPO_SAT; break;
        case 0b0010011: code = Hex_vdmpy, f = RP( W, H, H) | SS,    flags = IPO_SAT; break;
        case 0b0010100: code = Hex_vdmpy, f = RP( W, H, B) | DD|SS; break;
        case 0b0010101: code = Hex_vmpy,  f = RP( H,UB, B) | DD; break;
        case 0b0010110: code = Hex_vmpa,  f = RP( H,UB, B) | DD|SS; break;
        case 0b0010111: code = Hex_vmpa,  f = RP( W, H, B) | DD|SS; break;
        case 0b0011000: code = Hex_vdmpy, f = RP( W, H,UH),         flags = IAT_ADD | IPO_SAT; break;
        case 0b0011010: code = Hex_vdmpy, f = RP( W, H, H) | SS,    flags = IAT_ADD | IPO_SAT; break;
        case 0b0011011: code = Hex_vdmpy, f = RP( W, H, H),         flags = IAT_ADD | IPO_SAT; break;
        case 0b0011100: code = Hex_vdmpy, f = RP( W, H, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0011101: code = Hex_vmpy,  f = RP( H,UB, B) | DD,    flags = IAT_ADD; break;
        case 0b0011110: code = Hex_vmpa,  f = RP( H,UB, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0011111: code = Hex_vmpa,  f = RP( W, H, B) | DD|SS, flags = IAT_ADD; break;
        case 0b0100000: code = Hex_vmpy,  f = RP( W, H, H) | DD; break;
        case 0b0100001: code = Hex_vmpy,  f = RP( H, H, H),         flags = IPO_LS1_SAT; break;
        case 0b0100010: code = Hex_vmpy,  f = RP( H, H, H),         flags = IPO_LS1_RND_SAT; break;
        case 0b0100011: code = Hex_vmpy,  f = RP(UW,UH,UH) | DD; break;
        case 0b0101000: code = Hex_vmpy,  f = RP( W, H, H) | DD,    flags = IAT_ADD | IPO_SAT; break;
        case 0b0101001: code = Hex_vmpy,  f = RP(UW,UH,UH) | DD,    flags = IAT_ADD; break;
        case 0b0101010: code = Hex_vmpyi, f = RP( W, W, B),         flags = IAT_ADD; break;
        case 0b0101011: code = Hex_vmpyi, f = RP( W, W, H),         flags = IAT_ADD; break;
        case 0b0110000: code = Hex_vmpyi, f = RP( H, H, B); break;
        case 0b0110001: code = Hex_vror; break;
        case 0b0110010: code = Hex_vmpye, f = RP(UW,UH,UH); break;
        case 0b0110011: code = Hex_vmpa,  f = RP( H,UB,UB) | DD|SS; break;
        case 0b0110100: code = Hex_vlut4, f = RP( H,UH, H) | TT; break;
        case 0b0110101: code = Hex_vasr,  f = RP( W, W, _); break;
        case 0b0110110: code = Hex_vasr,  f = RP( H, H, _); break;
        case 0b0110111: code = Hex_vasl,  f = RP( W, W, _); break;
        case 0b0111000: code = Hex_vdsad, f = RP(UW,UH,UH) | DD|SS, flags = IAT_ADD; break;
        case 0b0111001: code = Hex_vmpyi, f = RP( H, H, B),         flags = IAT_ADD; break;
        case 0b0111010: code = Hex_vasl,  f = RP( W, W, _),         flags = IAT_ADD; break;
        case 0b0111101: code = Hex_vasr,  f = RP( W, W, _),         flags = IAT_ADD; break;
        case 0b1000000: code = Hex_vasl,  f = RP( H, H, _); break;
        case 0b1000001: code = Hex_vlsr,  f = RP(UW,UW, _); break;
        case 0b1000010: code = Hex_vlsr,  f = RP(UH,UH, _); break;
        case 0b1000011: code = Hex_vlsr,  f = RP(UB,UB, _); break;
        case 0b1000101: code = Hex_vmpa,  f = RP( W,UH, B) | DD|SS; break;
        case 0b1000110: code = Hex_vmpyi, f = RP( W, W,UB); break;
        case 0b1000111: code = Hex_vmpyi, f = RP( W, W, H); break;
        case 0b1001000: code = Hex_vmpy,  f = RP(UH,UB,UB) | DD,    flags = IAT_ADD; break;
        case 0b1001001: code = Hex_vmpyi, f = RP( W, W,UB),         flags = IAT_ADD; break;
        case 0b1001010: code = Hex_vmpa,  f = RP( W,UH, B) | DD|SS, flags = IAT_ADD; break;
        case 0b1001011: code = Hex_vmpye, f = RP(UW,UH,UH),         flags = IAT_ADD; break;
        case 0b1001100: code = Hex_vmpa3, f = RP( H, H, H) | TT,    flags = IPO_SAT; break;
        case 0b1001101: code = Hex_vmpa3, f = RP( H,UH,UH) | TT,    flags = IPO_SAT; break;
        case 0b1001110: code = Hex_vmps,  f = RP( H,UH,UH) | TT,    flags = IPO_SAT; break;
        case 0b1001111: code = Hex_vasr,  f = RP( H, H, _),         flags = IAT_ADD; break;
        case 0b1010000: code = Hex_vmpyi, f = RP( W, W, B); break;
        case 0b1010100: code = Hex_vtmpy, f = RP( W, H, B) | DD|SS; break;
        case 0b1011000: code = Hex_vrmpy, f = RP( W, B,UB) | DD|TT, flags = IAT_ADD; break;
        case 0b1011100: code = Hex_vmpa,  f = RP( H,UB,UB) | DD|SS, flags = IAT_ADD; break;
        case 0b1011101: code = Hex_vasl,  f = RP( H, H, _),         flags = IAT_ADD; break;
        case 0b1011110: code = Hex_vmpy,  f = RP( W, H, H) | DD,    flags = IAT_ADD; break;
        case 0b1011111: code = Hex_vrmpy, f = RP(UW,UB,UB) | DD|TT, flags = IAT_ADD; break;
        case 0b1100000: code = Hex_vmpy,  f = RP(UH,UB,UB) | DD; break;
        case 0b1100100: code = Hex_vrmpy, f = RP(UW,UB,UB) | DD|TT; break;
        case 0b1100101: code = Hex_vrmpy, f = RP( W, B,UB) | DD|TT; break;
        default: return 0;
        }
        op_reg( ops[0], REG_V(d5), FLG_D(f) );
        op_reg( ops[1], REG_V(u5), FLG_S(f) );
        op_reg( ops[2], REG_R(s5), FLG_T(f) );
        return code;

    case 0b010:
        if( (BITS(23:16) & 0b11011111) == 0b00000000 && BIT(13) == 0 && BIT(7) == 0 )
        {
            // if ([!]Ps4) Vd32 = Vu32
            op_reg( ops[PRED_A], REG_P(BITS(6:5)), BIT(21)? REG_PRE_NOT : 0 );
            op_reg( ops[0], REG_V(d5) );
            op_reg( ops[1], REG_V(u5) );
            flags = PRED_REG;
            return Hex_mov;
        }
        if( BITS(23:22) == 0b01 && BIT(13) == 0 && BIT(7) == 0 )
        {
            // if ([!]Ps4) Vdd32 = vcombine(Vu32,Vv32)
            op_reg( ops[PRED_A], REG_P(BITS(6:5)), BIT(21)? 0 : REG_PRE_NOT );
            op_reg( ops[0], REG_V(d5), REG_DOUBLE );
            op_reg( ops[1], REG_V(u5) );
            op_reg( ops[2], REG_V(s5) );
            flags = PRED_REG;
            return Hex_vcombine;
        }
        break;

    case 0b011:
        // miscellaneous 3-argument ops
        switch( (BITS(7:5) << 1) | BIT(13) )
        {
        case 0b0000: code = Hex_valign;  break;
        case 0b0001: code = Hex_vasr3,   f = RP( B, H, H),      flags = IPO_RND_SAT; break;
        case 0b0010: code = Hex_vlalign; break;
        case 0b0011: code = Hex_vlut32,  f = RP( B, B, B); break;
        case 0b0100: code = Hex_vasr3,   f = RP( H, W, W); break;
        case 0b0110: code = Hex_vasr3,   f = RP( H, W, W),      flags = IPO_SAT; break;
        case 0b0111: code = Hex_vshuff4, f = DD; break;
        case 0b1000: code = Hex_vasr3,   f = RP( H, W, W),      flags = IPO_RND_SAT; break;
        case 0b1001: code = Hex_vdeal4,  f = DD; break;
        case 0b1010: code = Hex_vasr3,   f = RP(UH, W, W),      flags = IPO_SAT; break;
        case 0b1011: code = Hex_vlut32,  f = RP( B, B, B),      flags = IAT_OR; break;
        case 0b1100: code = Hex_vasr3,   f = RP(UB, H, H),      flags = IPO_SAT; break;
        case 0b1101: code = Hex_vlut16,  f = RP( H, B, H) | DD; break;
        case 0b1110: code = Hex_vasr3,   f = RP(UB, H, H),      flags = IPO_RND_SAT; break;
        case 0b1111: code = Hex_vlut16,  f = RP( H, B, H) | DD, flags = IAT_OR; break;
        default: return 0;
        }
        op_reg( ops[0], REG_V(d5), FLG_D(f) );
        op_reg( ops[1], REG_V(u5), FLG_S(f) );
        op_reg( ops[2], REG_V(v5), FLG_T(f) );
        op_reg( ops[3], REG_R(t3) );
        return code;

    case 0b100:
        if( BITS(23:21) == 0b100 && BIT(13) == 1 && BITS(7:6) != 3 && BITS(5:4) != 3 && BITS(3:2) != 3 )
        {
            // Qd4 [*]= vcmp%c(Vu32.[u]{b|h|w},Vv32.[u]{b|h|w})
            static const uint8_t ass[] = { IAT_AND, IAT_OR, IAT_XOR };
            static const uint8_t rtypes[8] = {
                REG_POST_B,  REG_POST_H,  REG_POST_W,  0,
                REG_POST_UB, REG_POST_UH, REG_POST_UW, 0,
            };
            uint32_t type = rtypes[ (BIT(5) << 2) | BITS(3:2) ];

            op_reg( ops[0], REG_Q(BITS(1:0)) );
            op_reg( ops[1], REG_V(u5), type );
            op_reg( ops[2], REG_V(s5), type );
            flags = ((BITS(5:4)? CMP_GT : CMP_EQ)) | ass[ BITS(7:6) ];
            return Hex_vcmp;
        }
        if( BITS(23:21) == 0b101 && BIT(13) == 1 )
        {
            // Vd32.w = v{add|sub}(Vu32.w,Vv32.w,Qx4):carry or
            op_reg( ops[0], REG_V(d5), REG_POST_W );
            op_reg( ops[1], REG_V(u5), REG_POST_W );
            op_reg( ops[2], REG_V(s5), REG_POST_W );
            op_reg( ops[3], REG_Q(BITS(6:5)) );
            flags = IPO_CARRY;
            return BIT(7)? Hex_vsub3 : Hex_vadd3;
        }
        if( BITS(23:22) == 0b11 && BIT(13) == 1 )
        {
            // Vx[x]32.{b|h} |= vlut{16|32}(Vu32.b,Vv32.{b|h},#Ii)
            op_reg( ops[0], REG_V(d5), BIT(21)? REG_DOUBLE | REG_POST_H : REG_POST_B );
            op_reg( ops[1], REG_V(u5), REG_POST_B );
            op_reg( ops[2], REG_V(s5), BIT(21)? REG_POST_H : REG_POST_B );
            op_imm( ops[3], BITS(7:5) );
            flags = IAT_OR;
            return BIT(21)? Hex_vlut16 : Hex_vlut32;
        }
        break;

    case 0b101:
        if( BITS(23:21) == 0b100 && BIT(13) == 1 && BIT(7) == 0 )
        {
            // Vd32.w = vadd(Vu32.w,Vv32.w,Qs4):carry:sat
            op_reg( ops[0], REG_V(d5), REG_POST_W );
            op_reg( ops[1], REG_V(u5), REG_POST_W );
            op_reg( ops[2], REG_V(s5), REG_POST_W );
            op_reg( ops[3], REG_Q(BITS(6:5)) );
            flags = IPO_CARRY_SAT;
            return Hex_vadd3;
        }
        if( BITS(23:21) == 0b101 && BIT(13) == 1 )
        {
            // Vd32.w,Qe4 = v{add|sub}(Vu32.w,Vv32.w):carry
            op_reg( ops[0], REG_V(d5), REG_POST_W );
            op_reg( ops[1], REG_Q(BITS(6:5)) );
            op_reg( ops[2], REG_V(u5), REG_POST_W );
            op_reg( ops[3], REG_V(s5), REG_POST_W );
            flags = IPO_CARRY;
            return BIT(7)? Hex_vsub2d : Hex_vadd2d;
        }
        break;

    case 0b110:
        if( (BITS(21:16) & 0b111101) == 0 && BITS(13:11) == 0b100 &&
            BITS(7:0) == 0b10000000 && (BIT(17) || !BITS(23:22)) )
        {
            // v[w]hist[128|256]([Qv4,][#Ii])[:sat]
            static const uint16_t itype[8] = {
                Hex_vhist,  Hex_vwhist256,   Hex_vwhist128,   Hex_vwhist128_1,
                Hex_vhist1, Hex_vwhist256_1, Hex_vwhist128_1, Hex_vwhist128_2,
            };
            if( BIT(17) ) {
                op_reg( ops[0], REG_Q(BITS(23:22)) );
                op_imm( ops[1], BIT(8) );
            }
            else
                op_imm( ops[0], BIT(8) );
            if( BITS(10:8) == 0b011 ) flags = IPO_SAT;
            return itype[ (BIT(17) << 2) | BITS(10:9) ];
        }
        if( BITS(23:16) == 0b00000011 && BIT(13) == 1 && BITS(7:5) == 0b111 )
        {
            // Vd32 = Vu32
            op_reg( ops[0], REG_V(d5) );
            op_reg( ops[1], REG_V(u5) );
            return Hex_mov;
        }
        if( BITS(21:18) == 0 && (BIT(17) ^ BIT(16)) == 1 && BIT(13) == 1 )
        {
            // if ([!]Qv4) Vx32.{b|h|w} ±= Vu32.{b|h|w}
            uint32_t code = (BIT(17) << 3) | BITS(7:5);
            uint32_t rf = REG_POST_B + ((code % 3) << REG_POST_SHIFT);
            op_reg( ops[PRED_A], REG_Q(BITS(23:22)), (code / 3 & 1)? REG_PRE_NOT : 0 );
            op_reg( ops[0], REG_V(d5), rf );
            op_reg( ops[1], REG_V(u5), rf );
            flags = PRED_REG | (code < 6? IAT_ADD : IAT_SUB);
            return Hex_mov;
        }
        if( (BITS(23:21) & 0b101) == 0b001 )
        {
            // Vd[d]32.{b|h} = vlut{16|32}(Vu32.b,Vv32.{b|h},#Ii) or
            // Vd32 = v[l]align(Vu32,Vv32,#Ii)
            switch( (BIT(13) << 1) | BIT(22) )
            {
            case 0b00: code = Hex_vlut32, f = RP(B, B, B); break;
            case 0b01: code = Hex_vlut16, f = RP(H, B, H) | DD; break;
            case 0b10: code = Hex_valign; break;
            case 0b11: code = Hex_vlalign; break;
            }
            op_reg( ops[0], REG_V(d5), FLG_D(f) );
            op_reg( ops[1], REG_V(u5), FLG_S(f) );
            op_reg( ops[2], REG_V(s5), FLG_T(f) );
            op_imm( ops[3], BITS(7:5) );
            return code;
        }
        if( BITS(21:16) == 0b000011 && (BITS(13:5) & 0b111100111) == 0b100000010 &&
            BITS(9:8) != 3 )
        {
            // Vd32.{b|h|w} = prefixsum(Qv4)
            op_reg( ops[0], REG_V(d5), REG_POST_B + (BITS(9:8) << REG_POST_SHIFT) );
            op_reg( ops[1], REG_Q(BITS(23:22)) );
            return Hex_prefixsum;
        }
        if( BITS(21:16) == 0b000011 && BITS(13:10) == 0 && BITS(7:5) == 0 )
        {
            // Qd4 = <logic>(Qs4,[!]Qt4) or Qd4.{b|h} = vshuffe(Qs4.{h|w},Qt4.{h|w})
            switch( BITS(4:2) )
            {
            case 0: code = Hex_and; break;
            case 1: code = Hex_or; break;
            case 2: code = Hex_not; break;
            case 3: code = Hex_xor; break;
            case 4: code = Hex_or, f = REG_PRE_NOT << 20; break;
            case 5: code = Hex_and, f = REG_PRE_NOT << 20; break;
            case 6: code = Hex_vshuffe, f = RP(B, H, H); break;
            case 7: code = Hex_vshuffe, f = RP(H, W, W); break;
            }
            op_reg( ops[0], REG_Q(BITS(1:0)), FLG_D(f) );
            op_reg( ops[1], REG_Q(BITS(9:8)), FLG_S(f) );
            op_reg( ops[2], REG_Q(BITS(23:22)), FLG_T(f) );
            return code;
        }
        if( (BITS(23:21) & 0b101) == 0b101 && BIT(13) == 1 && BIT(7) == 0 )
        {
            // Vd[d]32 = v{swap|mux}(Qt4,Vu32,Vv32)
            op_reg( ops[0], REG_V(d5), BIT(22)? 0 : REG_DOUBLE );
            op_reg( ops[1], REG_Q(BITS(6:5)) );
            op_reg( ops[2], REG_V(u5) );
            op_reg( ops[3], REG_V(s5) );
            return BIT(22)? Hex_vmux : Hex_vswap;
        }
        if( BITS(21:16) == 0b000011 && BIT(13) == 1 && BITS(7:6) == 0 )
        {
            // Vd32 = vand([!]Qv4,Vu32)
            op_reg( ops[0], REG_V(d5) );
            op_reg( ops[1], REG_Q(BITS(23:22)), BIT(5)? REG_PRE_NOT : 0 );
            op_reg( ops[2], REG_V(u5) );
            return Hex_vand;
        }
        if( BITS(23:16) == 0b00000000 && BIT(13) == 1 && BITS(7:6) == 0 )
        {
            // Vxx32.{h|w} |= vunpacko(Vu32.{b|h})
            op_reg( ops[0], REG_V(d5), BIT(5)? REG_POST_W : REG_POST_H );
            op_reg( ops[1], REG_V(u5), BIT(5)? REG_POST_H : REG_POST_B );
            flags = IAT_OR;
            return Hex_vunpacko;
        }
        // all other single-argument instructions
        if( BITS(23:18) == 0b000000 && BIT(13) == 0 )
        {
            // Vd32[.xx] = <op>(Vu32[.xx])
            switch( (BITS(17:16) << 3) | BITS(7:5) )
            {
               case 0b00000: code = Hex_vabs,      f = RP( H, H, _); break;
               case 0b00001: code = Hex_vabs,      f = RP( H, H, _), flags = IPO_SAT; break;
               case 0b00010: code = Hex_vabs,      f = RP( W, W, _); break;
               case 0b00011: code = Hex_vabs,      f = RP( W, W, _), flags = IPO_SAT; break;
               case 0b00100: code = Hex_vnot,      f = RP( _, _, _); break;
               case 0b00110: code = Hex_vdeal,     f = RP( H, H, _); break;
               case 0b00111: code = Hex_vdeal,     f = RP( B, B, _); break;
               case 0b01000: code = Hex_vunpack,   f = RP(UH,UB, _) | DD; break;
               case 0b01001: code = Hex_vunpack,   f = RP(UW,UH, _) | DD; break;
               case 0b01010: code = Hex_vunpack,   f = RP( H, B, _) | DD; break;
               case 0b01011: code = Hex_vunpack,   f = RP( W, H, _) | DD; break;
               case 0b01100: code = Hex_vabs,      f = RP( B, B, _); break;
               case 0b01101: code = Hex_vabs,      f = RP( B, B, _), flags = IPO_SAT; break;
               case 0b01111: code = Hex_vshuff,    f = RP( H, H, _); break;
               case 0b10000: code = Hex_vshuff,    f = RP( B, B, _); break;
               case 0b10001: code = Hex_vzxt,      f = RP(UH,UB, _) | DD; break;
               case 0b10010: code = Hex_vzxt,      f = RP(UW,UH, _) | DD; break;
               case 0b10011: code = Hex_vsxt,      f = RP( H, B, _) | DD; break;
               case 0b10100: code = Hex_vsxt,      f = RP( W, H, _) | DD; break;
               case 0b10101: code = Hex_vcl0,      f = RP(UW,UW, _); break;
               case 0b10110: code = Hex_vpopcount, f = RP( H, H, _); break;
               case 0b10111: code = Hex_vcl0,      f = RP(UH,UH, _); break;
               case 0b11100: code = Hex_vnormamt,  f = RP( W, W, _); break;
               case 0b11101: code = Hex_vnormamt,  f = RP( H, H, _); break;
               default: return 0;
            }
            op_reg( ops[0], REG_V(d5), FLG_D(f) );
            op_reg( ops[1], REG_V(u5), FLG_S(f) );
            return code;
        }
        break;

    case 0b111:
        if( BITS(23:21) == 0b100 && BIT(13) == 0 && BITS(7:4) <= 2 && BITS(3:2) != 3 )
        {
            // Qd4 = vcmp%c(Vu32.[u]{b|h|w},Vv32.[u]{b|h|w})
            static const uint8_t rtypes[8] = {
                REG_POST_B,  REG_POST_H,  REG_POST_W,  0,
                REG_POST_UB, REG_POST_UH, REG_POST_UW, 0,
            };
            uint32_t type = rtypes[ (BIT(5) << 2) | BITS(3:2) ];

            op_reg( ops[0], REG_Q(BITS(1:0)) );
            op_reg( ops[1], REG_V(u5), type );
            op_reg( ops[2], REG_V(s5), type );
            flags = (BITS(5:4)? CMP_GT : CMP_EQ);
            return Hex_vcmp;
        }
        break;
    }

    // all the remaining instructions
    switch( (BITS(26:21) << 4) | (BIT(13) << 3) | BITS(7:5) )
    {
    case 0b0101001111: code = Hex_vrotr,    f = RP(UW,UW,UW); break;
    case 0b0101011111: code = Hex_vasrinto, f = RP( W, W, W) | DD; break;
    case 0b1000000000: code = Hex_vrmpy,    f = RP(UW,UB,UB); break;
    case 0b1000000001: code = Hex_vrmpy,    f = RP( W, B, B); break;
    case 0b1000000010: code = Hex_vrmpy,    f = RP( W,UB, B); break;
    case 0b1000000011: code = Hex_vdmpy,    f = RP( W, H, H), flags = IPO_SAT; break;
    case 0b1000000100: code = Hex_vmpy,     f = RP( H, B, B) | DD; break;
    case 0b1000000101: code = Hex_vmpy,     f = RP(UH,UB,UB) | DD; break;
    case 0b1000000110: code = Hex_vmpy,     f = RP( H,UB, B) | DD; break;
    case 0b1000000111: code = Hex_vmpy,     f = RP( W, H, H) | DD; break;
    case 0b1000001000: code = Hex_vrmpy,    f = RP(UW,UB,UB), flags = IAT_ADD; break;
    case 0b1000001001: code = Hex_vrmpy,    f = RP( W, B, B), flags = IAT_ADD; break;
    case 0b1000001010: code = Hex_vrmpy,    f = RP( W,UB, B), flags = IAT_ADD; break;
    case 0b1000001011: code = Hex_vdmpy,    f = RP( W, H, H), flags = IAT_ADD | IPO_SAT; break;
    case 0b1000001100: code = Hex_vmpy,     f = RP( H, B, B) | DD, flags = IAT_ADD; break;
    case 0b1000001101: code = Hex_vmpy,     f = RP(UH,UB,UB) | DD, flags = IAT_ADD; break;
    case 0b1000001110: code = Hex_vmpy,     f = RP( H,UB, B) | DD, flags = IAT_ADD; break;
    case 0b1000001111: code = Hex_vmpy,     f = RP( W, H, H) | DD, flags = IAT_ADD; break;
    case 0b1000010000: code = Hex_vmpy,     f = RP(UW,UH,UH) | DD; break;
    case 0b1000010001: code = Hex_vmpy,     f = RP( H, H, H), flags = IPO_LS1_RND_SAT; break;
    case 0b1000010010: code = Hex_vmpy,     f = RP( W, H,UH) | DD; break;
    case 0b1000010011: code = Hex_vmpa,     f = RP( H,UB, B) | DD|SS|TT; break;
    case 0b1000010100: code = Hex_vmpyi,    f = RP( H, H, H); break;
    case 0b1000010101: code = Hex_vand;     break;
    case 0b1000010110: code = Hex_vor;      break;
    case 0b1000010111: code = Hex_vxor;     break;
    case 0b1000011000: code = Hex_vmpy,     f = RP(UW,UH,UH) | DD, flags = IAT_ADD; break;
    case 0b1000011001: code = Hex_vmpy,     f = RP( W, H,UH) | DD, flags = IAT_ADD; break;
    case 0b1000011010: code = Hex_vadd,     f = RP( W, H, H) | DD, flags = IAT_ADD; break;
    case 0b1000011011: code = Hex_vmpyo,    f = RP( _, W, H) | DD, flags = IAT_ADD; break;
    case 0b1000011100: code = Hex_vmpyi,    f = RP( H, H, H), flags = IAT_ADD; break;
    case 0b1000011101: code = Hex_vmpyie,   f = RP( W, W,UH), flags = IAT_ADD; break;
    case 0b1000011110: code = Hex_vmpyo,    f = RP( W, W, H), flags = IAT_ADD | IPO_LS1_SAT_SHIFT; break;
    case 0b1000011111: code = Hex_vmpyo,    f = RP( W, W, H), flags = IAT_ADD | IPO_LS1_RND_SAT_SHIFT; break;
    case 0b1000100000: code = Hex_vadd,     f = RP( W, W, W); break;
    case 0b1000100001: code = Hex_vadd,     f = RP(UB,UB,UB), flags = IPO_SAT; break;
    case 0b1000100010: code = Hex_vadd,     f = RP(UH,UH,UH), flags = IPO_SAT; break;
    case 0b1000100011: code = Hex_vadd,     f = RP( H, H, H), flags = IPO_SAT; break;
    case 0b1000100100: code = Hex_vadd,     f = RP( W, W, W), flags = IPO_SAT; break;
    case 0b1000100101: code = Hex_vsub,     f = RP( B, B, B); break;
    case 0b1000100110: code = Hex_vsub,     f = RP( H, H, H); break;
    case 0b1000100111: code = Hex_vsub,     f = RP( W, W, W); break;
    case 0b1000101000: code = Hex_vmpyie,   f = RP( W, W, H), flags = IAT_ADD; break;
    case 0b1000101100: code = Hex_vadd,     f = RP( W,UH,UH) | DD, flags = IAT_ADD; break;
    case 0b1000101101: code = Hex_vadd,     f = RP( H,UB,UB) | DD, flags = IAT_ADD; break;
    case 0b1000110000: code = Hex_vsub,     f = RP(UB,UB,UB), flags = IPO_SAT; break;
    case 0b1000110001: code = Hex_vsub,     f = RP(UH,UH,UH), flags = IPO_SAT; break;
    case 0b1000110010: code = Hex_vsub,     f = RP( H, H, H), flags = IPO_SAT; break;
    case 0b1000110011: code = Hex_vsub,     f = RP( W, W, W), flags = IPO_SAT; break;
    case 0b1000110100: code = Hex_vadd,     f = RP( B, B, B) | DD|SS|TT; break;
    case 0b1000110101: code = Hex_vadd,     f = RP( H, H, H) | DD|SS|TT; break;
    case 0b1000110110: code = Hex_vadd,     f = RP( W, W, W) | DD|SS|TT; break;
    case 0b1000110111: code = Hex_vadd,     f = RP(UB,UB,UB) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001000000: code = Hex_vadd,     f = RP(UH,UH,UH) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001000001: code = Hex_vadd,     f = RP( H, H, H) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001000010: code = Hex_vadd,     f = RP( W, W, W) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001000011: code = Hex_vsub,     f = RP( B, B, B) | DD|SS|TT; break;
    case 0b1001000100: code = Hex_vsub,     f = RP( H, H, H) | DD|SS|TT; break;
    case 0b1001000101: code = Hex_vsub,     f = RP( W, W, W) | DD|SS|TT; break;
    case 0b1001000110: code = Hex_vsub,     f = RP(UB,UB,UB) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001000111: code = Hex_vsub,     f = RP(UH,UH,UH) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001010000: code = Hex_vsub,     f = RP( H, H, H) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001010001: code = Hex_vsub,     f = RP( W, W, W) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1001010010: code = Hex_vadd,     f = RP( H,UB,UB) | DD; break;
    case 0b1001010011: code = Hex_vadd,     f = RP( W,UH,UH) | DD; break;
    case 0b1001010100: code = Hex_vadd,     f = RP( W, H, H) | DD; break;
    case 0b1001010101: code = Hex_vsub,     f = RP( H,UB,UB) | DD; break;
    case 0b1001010110: code = Hex_vsub,     f = RP( W,UH,UH) | DD; break;
    case 0b1001010111: code = Hex_vsub,     f = RP( W, H, H) | DD; break;
    case 0b1001100000: code = Hex_vabsdiff, f = RP(UB,UB,UB); break;
    case 0b1001100001: code = Hex_vabsdiff, f = RP(UH, H, H); break;
    case 0b1001100010: code = Hex_vabsdiff, f = RP(UH,UH,UH); break;
    case 0b1001100011: code = Hex_vabsdiff, f = RP(UW, W, W); break;
    case 0b1001100100: code = Hex_vavg,     f = RP(UB,UB,UB); break;
    case 0b1001100101: code = Hex_vavg,     f = RP(UH,UH,UH); break;
    case 0b1001100110: code = Hex_vavg,     f = RP( H, H, H); break;
    case 0b1001100111: code = Hex_vavg,     f = RP( W, W, W); break;
    case 0b1001110000: code = Hex_vnavg,    f = RP( B,UB,UB); break;
    case 0b1001110001: code = Hex_vnavg,    f = RP( H, H, H); break;
    case 0b1001110010: code = Hex_vnavg,    f = RP( W, W, W); break;
    case 0b1001110011: code = Hex_vavg,     f = RP(UB,UB,UB), flags = IPO_RND; break;
    case 0b1001110100: code = Hex_vavg,     f = RP(UH,UH,UH), flags = IPO_RND; break;
    case 0b1001110101: code = Hex_vavg,     f = RP( H, H, H), flags = IPO_RND; break;
    case 0b1001110110: code = Hex_vavg,     f = RP( W, W, W), flags = IPO_RND; break;
    case 0b1001110111: code = Hex_vmpa,     f = RP( H,UB,UB) | DD|SS|TT; break;
    case 0b1011001111: code = Hex_vsatdw,   f = RP( W, W, W); break;
    case 0b1101010000: code = Hex_vadd,     f = RP( B, B, B) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1101010001: code = Hex_vsub,     f = RP( B, B, B) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1101010010: code = Hex_vadd,     f = RP(UW,UW,UW) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1101010011: code = Hex_vsub,     f = RP(UW,UW,UW) | DD|SS|TT, flags = IPO_SAT; break;
    case 0b1101010100: code = Hex_vadd,     f = RP(UB,UB, B), flags = IPO_SAT; break;
    case 0b1101010101: code = Hex_vsub,     f = RP(UB,UB, B), flags = IPO_SAT; break;
    case 0b1101010110: code = Hex_vmpye,    f = RP( _, W,UH) | DD; break;
    case 0b1110000000: code = Hex_vadd,     f = RP( B, B, B), flags = IPO_SAT; break;
    case 0b1110000001: code = Hex_vmin,     f = RP(UB,UB,UB); break;
    case 0b1110000010: code = Hex_vmin,     f = RP(UH,UH,UH); break;
    case 0b1110000011: code = Hex_vmin,     f = RP( H, H, H); break;
    case 0b1110000100: code = Hex_vmin,     f = RP( W, W, W); break;
    case 0b1110000101: code = Hex_vmax,     f = RP(UB,UB,UB); break;
    case 0b1110000110: code = Hex_vmax,     f = RP(UH,UH,UH); break;
    case 0b1110000111: code = Hex_vmax,     f = RP( H, H, H); break;
    case 0b1110001000: code = Hex_vaddclb,  f = RP( H, H, H); break;
    case 0b1110001001: code = Hex_vaddclb,  f = RP( W, W, W); break;
    case 0b1110001010: code = Hex_vavg,     f = RP(UW,UW,UW); break;
    case 0b1110001011: code = Hex_vavg,     f = RP(UW,UW,UW), flags = IPO_RND; break;
    case 0b1110001100: code = Hex_vavg,     f = RP( B, B, B); break;
    case 0b1110001101: code = Hex_vavg,     f = RP( B, B, B), flags = IPO_RND; break;
    case 0b1110001110: code = Hex_vnavg,    f = RP( B, B, B); break;
    case 0b1110010000: code = Hex_vmax,     f = RP( W, W, W); break;
    case 0b1110010001: code = Hex_vdelta;   break;
    case 0b1110010010: code = Hex_vsub,     f = RP( B, B, B), flags = IPO_SAT; break;
    case 0b1110010011: code = Hex_vrdelta;  break;
    case 0b1110010100: code = Hex_vmin,     f = RP( B, B, B); break;
    case 0b1110010101: code = Hex_vmax,     f = RP( B, B, B); break;
    case 0b1110010110: code = Hex_vsat,     f = RP(UH,UW,UW); break;
    case 0b1110010111: code = Hex_vdeale,   f = RP( B, B, B); break;
    case 0b1110100000: code = Hex_vmpyo,    f = RP( W, W, H), flags = IPO_LS1_RND_SAT; break;
    case 0b1110100001: code = Hex_vshuffe,  f = RP( B, B, B); break;
    case 0b1110100010: code = Hex_vshuffo,  f = RP( B, B, B); break;
    case 0b1110100011: code = Hex_vshuffe,  f = RP( H, H, H); break;
    case 0b1110100100: code = Hex_vshuffo,  f = RP( H, H, H); break;
    case 0b1110100101: code = Hex_vshuffoe, f = RP( H, H, H) | DD; break;
    case 0b1110100110: code = Hex_vshuffoe, f = RP( B, B, B) | DD; break;
    case 0b1110100111: code = Hex_vcombine, f = DD; break;
    case 0b1110110000: code = Hex_vmpyieo,  f = RP( W, H, H); break;
    case 0b1110110001: code = Hex_vadd,     f = RP(UW,UW,UW), flags = IPO_SAT; break;
    case 0b1110110010: code = Hex_vsat,     f = RP(UB, H, H); break;
    case 0b1110110011: code = Hex_vsat,     f = RP( H, W, W); break;
    case 0b1110110100: code = Hex_vround,   f = RP( H, W, W), flags = IPO_SAT; break;
    case 0b1110110101: code = Hex_vround,   f = RP(UH, W, W), flags = IPO_SAT; break;
    case 0b1110110110: code = Hex_vround,   f = RP( B, H, H), flags = IPO_SAT; break;
    case 0b1110110111: code = Hex_vround,   f = RP(UB, H, H), flags = IPO_SAT; break;
    case 0b1111010000: code = Hex_vasr,     f = RP( W, W, W); break;
    case 0b1111010001: code = Hex_vlsr,     f = RP( W, W, W); break;
    case 0b1111010010: code = Hex_vlsr,     f = RP( H, H, H); break;
    case 0b1111010011: code = Hex_vasr,     f = RP( H, H, H); break;
    case 0b1111010100: code = Hex_vasl,     f = RP( W, W, W); break;
    case 0b1111010101: code = Hex_vasl,     f = RP( H, H, H); break;
    case 0b1111010110: code = Hex_vadd,     f = RP( B, B, B); break;
    case 0b1111010111: code = Hex_vadd,     f = RP( H, H, H); break;
    case 0b1111100000: code = Hex_vmpyie,   f = RP( W, W,UH); break;
    case 0b1111100001: code = Hex_vmpyio,   f = RP( W, W, H); break;
    case 0b1111100010: code = Hex_vpacke,   f = RP( B, H, H); break;
    case 0b1111100011: code = Hex_vpacke,   f = RP( H, W, W); break;
    case 0b1111100100: code = Hex_vsub,     f = RP(UW,UW,UW), flags = IPO_SAT; break;
    case 0b1111100101: code = Hex_vpack,    f = RP(UB, H, H), flags = IPO_SAT; break;
    case 0b1111100110: code = Hex_vpack,    f = RP( B, H, H), flags = IPO_SAT; break;
    case 0b1111100111: code = Hex_vpack,    f = RP(UH, W, W), flags = IPO_SAT; break;
    case 0b1111110000: code = Hex_vpack,    f = RP( H, W, W), flags = IPO_SAT; break;
    case 0b1111110001: code = Hex_vpacko,   f = RP( B, H, H); break;
    case 0b1111110010: code = Hex_vpacko,   f = RP( H, W, W); break;
    case 0b1111110011: code = Hex_vround,   f = RP(UB,UH,UH), flags = IPO_SAT; break;
    case 0b1111110100: code = Hex_vround,   f = RP(UH,UW,UW), flags = IPO_SAT; break;
    case 0b1111110101: code = Hex_vmpye,    f = RP( W, W,UH); break;
    case 0b1111110111: code = Hex_vmpyo,    f = RP( W, W, H), flags = IPO_LS1_SAT; break;
    default: return 0;
    }
    op_reg( ops[0], REG_V(d5), FLG_D(f) );
    op_reg( ops[1], REG_V(u5), FLG_S(f) );
    op_reg( ops[2], REG_V(s5), FLG_T(f) );
    return code;
}

static uint32_t iclass_1_ZReg( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0), t3 = BITS(18:16);

    if( BITS(27:21) == 0b1001101 && BITS(13:5) == 0b000001001 )
    {
        // Vd32 = zextract(Rt32)
        op_reg( ops[0], REG_V(d5) );
        op_reg( ops[1], REG_R(s5) );
        return Hex_zextract;
    }
    if( BITS(27:22) == 0b100111 && (BIT(21) ^ BIT(13)) == 1 && BIT(7) == 0 )
    {
        // Vdddd32.w [+]= vr[8|16]mpyz[s](Vu32.{b|n|c},Rt8.[u]b[++])
        static const uint8_t conv[4] = { 255, 2, 0, 1 };
        uint32_t code = ((BIT(13)? conv[BITS(6:5)] : BITS(6:5)) << 1) | BIT(20);
        static const uint16_t itype[6] = {
            Hex_vrmpyz, Hex_vr8mpyz, Hex_vr16mpyz, 0,
            Hex_vr16mpyzs, Hex_vrmpyz,
        };
        op_reg( ops[0], REG_V(d5), REG_QUAD | REG_POST_W );
        op_reg( ops[1], REG_V(u5), code == 1? REG_POST_N :
                                   (code == 2 || code == 4)? REG_POST_C : REG_POST_B );
        op_reg( ops[2], REG_R(t3), (code == 5? REG_POST_UB : REG_POST_B) |
                                 ((BIT(21) ^ BIT(19))? REG_POST_INC : 0) );
        if( !BIT(21) ) flags = IAT_ADD;
        return code < _countof(itype)? itype[code] : 0;
    }
    return 0;
}

static uint32_t iclass_1_HVX_v68( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    if( BITS(27:26) != 0b11 || BIT(13) != 1 )
        return 0;

    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0), code, f;

    if( BITS(25:21) == 0b00100 )
    {
        // Qd4 [*]= vcmp.gt(Vu32.{sf|hf},Vv32.{sf|hf})
        switch( BITS(7:3) )
        {
        case 0b00110: flags = CMP_GT | IAT_OR;  break;
        case 0b01110: flags = CMP_GT | IAT_ASS; break;
        case 0b11001: flags = CMP_GT | IAT_AND; break;
        case 0b11101: flags = CMP_GT | IAT_XOR; break;
        default:      return 0;
        }
        uint32_t type = BIT(2)? REG_POST_HF : REG_POST_SF;
        op_reg( ops[0], REG_Q(BITS(1:0)) );
        op_reg( ops[1], REG_V(u5), type );
        op_reg( ops[2], REG_V(s5), type );
        return Hex_vcmp;
    }
    if( BITS(25:18) == 0b10000001 )
    {
        // various single argument FP insns
        switch( (BITS(17:16) << 3) | BITS(7:5) )
        {
        case 0b00000: code = Hex_mov,   f = RP(SF,Q32, _); break;
        case 0b00001: code = Hex_vcvt,  f = RP(HF, UB, _) | DD; break;
        case 0b00010: code = Hex_vcvt,  f = RP(HF,  B, _) | DD; break;
        case 0b00011: code = Hex_mov,   f = RP(HF,Q16, _); break;
        case 0b00100: code = Hex_vcvt,  f = RP(SF, HF, _) | DD; break;
        case 0b00101: code = Hex_vcvt,  f = RP(HF, UH, _); break;
        case 0b00110: code = Hex_mov,   f = RP(HF,Q32, _) | SS; break;
        case 0b00111: code = Hex_vcvt,  f = RP(HF,  H, _); break;
        case 0b01000: code = Hex_vcvt,  f = RP(UH, HF, _); break;
        case 0b10000: code = Hex_vcvt,  f = RP( H, HF, _); break;
        case 0b10001: code = Hex_vfmv,  f = RP( W,  W, _); break;
        case 0b10010: code = Hex_vfneg, f = RP(HF, HF, _); break;
        case 0b10011: code = Hex_vfneg, f = RP(SF, SF, _); break;
        case 0b10100: code = Hex_vabs,  f = RP(HF, HF, _); break;
        case 0b10101: code = Hex_vabs,  f = RP(SF, SF, _); break;
        default:      return 0;
        }
        op_reg( ops[0], REG_V(d5), FLG_D(f) );
        op_reg( ops[1], REG_V(u5), FLG_S(f) );
        return code;
    }
    if( BITS(25:23) == 0b110 && (BIT(22) ^ BIT(21)) == 1 )
    {
        // Vdd32.w [+]= v6mpy(Vuu32.ub,Vvv32.b,#u2):{v|h}
        op_reg( ops[0], REG_V(d5), REG_DOUBLE | REG_POST_W );
        op_reg( ops[1], REG_V(u5), REG_DOUBLE | REG_POST_UB );
        op_reg( ops[2], REG_V(s5), REG_DOUBLE | REG_POST_B );
        op_imm( ops[3], BITS(6:5) );
        flags = (BIT(21)? IAT_ADD : 0) |
                (BIT(7)?  IPO_H : IPO_V);
        return Hex_v6mpy;
    }

    // all the remaining instructions
    switch( (BITS(25:21) << 3) | BITS(7:5) )
    {
    case 0b00010001: code = Hex_vmpy,  f = RP( SF, HF, HF) | DD, flags = IAT_ADD; break;
    case 0b00010010: code = Hex_vmpy,  f = RP( HF, HF, HF), flags = IAT_ADD; break;
    case 0b00010011: code = Hex_vdmpy, f = RP( SF, HF, HF), flags = IAT_ADD; break;
    case 0b00011000: code = Hex_vfmin, f = RP( HF, HF, HF); break;
    case 0b00011001: code = Hex_vfmin, f = RP( SF, SF, SF); break;
    case 0b00011010: code = Hex_vfmax, f = RP( HF, HF, HF); break;
    case 0b00011011: code = Hex_vfmax, f = RP( SF, SF, SF); break;
    case 0b11011000: code = Hex_vsub,  f = RP( HF, HF, HF); break;
    case 0b11011001: code = Hex_vcvt2, f = RP( HF, SF, SF); break;
    case 0b11011010: code = Hex_vadd,  f = RP(Q16,Q16,Q16); break;
    case 0b11011011: code = Hex_vadd,  f = RP(Q16, HF, HF); break;
    case 0b11011100: code = Hex_vadd,  f = RP(Q16,Q16, HF); break;
    case 0b11011101: code = Hex_vsub,  f = RP(Q16,Q16,Q16); break;
    case 0b11011110: code = Hex_vsub,  f = RP(Q16, HF, HF); break;
    case 0b11011111: code = Hex_vsub,  f = RP(Q16,Q16, HF); break;
    case 0b11100000: code = Hex_vmpy,  f = RP(Q32,Q16, HF) | DD; break;
    case 0b11100001: code = Hex_vmpy,  f = RP( SF, SF, SF); break;
    case 0b11100010: code = Hex_vmpy,  f = RP( SF, HF, HF) | DD; break;
    case 0b11100011: code = Hex_vmpy,  f = RP( HF, HF, HF); break;
    case 0b11100100: code = Hex_vadd,  f = RP( SF, HF, HF) | DD; break;
    case 0b11100101: code = Hex_vsub,  f = RP( SF, HF, HF) | DD; break;
    case 0b11100110: code = Hex_vadd,  f = RP( SF, SF, SF); break;
    case 0b11100111: code = Hex_vsub,  f = RP( SF, SF, SF); break;
    case 0b11101000: code = Hex_vadd,  f = RP(Q32,Q32,Q32); break;
    case 0b11101001: code = Hex_vadd,  f = RP(Q32, SF, SF); break;
    case 0b11101010: code = Hex_vadd,  f = RP(Q32,Q32, SF); break;
    case 0b11101011: code = Hex_vsub,  f = RP(Q32,Q32,Q32); break;
    case 0b11101100: code = Hex_vsub,  f = RP(Q32, SF, SF); break;
    case 0b11101101: code = Hex_vsub,  f = RP(Q32,Q32, SF); break;
    case 0b11101110: code = Hex_vdmpy, f = RP( SF, HF, HF); break;
    case 0b11101111: code = Hex_vadd,  f = RP( HF, HF, HF); break;
    case 0b11110001: code = Hex_vmax,  f = RP( SF, SF, SF); break;
    case 0b11110010: code = Hex_vmin,  f = RP( SF, SF, SF); break;
    case 0b11110011: code = Hex_vmax,  f = RP( HF, HF, HF); break;
    case 0b11110100: code = Hex_vmin,  f = RP( HF, HF, HF); break;
    case 0b11110101: code = Hex_vcvt2, f = RP( UB, HF, HF); break;
    case 0b11110110: code = Hex_vcvt2, f = RP(  B, HF, HF); break;
    case 0b11111000: code = Hex_vmpy,  f = RP(Q32,Q32,Q32); break;
    case 0b11111001: code = Hex_vmpy,  f = RP(Q32, SF, SF); break;
    case 0b11111011: code = Hex_vmpy,  f = RP(Q16,Q16,Q16); break;
    case 0b11111100: code = Hex_vmpy,  f = RP(Q16, HF, HF); break;
    case 0b11111101: code = Hex_vmpy,  f = RP(Q16,Q16, HF); break;
    case 0b11111110: code = Hex_vmpy,  f = RP(Q32,Q16,Q16) | DD; break;
    case 0b11111111: code = Hex_vmpy,  f = RP(Q32, HF, HF) | DD; break;
    default: return 0;
    }
    op_reg( ops[0], REG_V(d5), FLG_D(f) );
    op_reg( ops[1], REG_V(u5), FLG_S(f) );
    op_reg( ops[2], REG_V(s5), FLG_T(f) );
    return code;
}

static uint32_t iclass_1_HVX_v69( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0);

    if( BITS(27:21) == 0b1101000 && BIT(13) == 0 && BIT(7) == 0 )
    {
        // Vd32.{uh|ub} = vasr(Vuu32.{w|uh},Vv32.{uh|ub})[:rnd]:sat
        op_reg( ops[0], REG_V(d5), BIT(6)? REG_POST_UB : REG_POST_UH );
        op_reg( ops[1], REG_V(u5), REG_DOUBLE | (BIT(6)? REG_POST_UH : REG_POST_W) );
        op_reg( ops[2], REG_V(s5), BIT(6)? REG_POST_UB : REG_POST_UH );
        flags = BIT(5)? IPO_RND_SAT : IPO_SAT;
        return Hex_vasr;
    }
    if( BITS(27:21) == 0b1110000 && BITS(20:16) == 0b00001 && BIT(13) == 0 && BITS(7:5) == 0b110 )
    {
        // Vd32.tmp = Vu32
        op_reg( ops[0], REG_V(d5), REG_POST_TMP );
        op_reg( ops[1], REG_V(u5) );
        return Hex_mov;
    }
    if( BITS(27:21) == 0b1110101 && BIT(13) == 0 && BITS(7:5) == 0b111 )
    {
        // Vdd32.tmp = vcombine(Vu32,Vv32)
        op_reg( ops[0], REG_V(d5), REG_DOUBLE | REG_POST_TMP );
        op_reg( ops[1], REG_V(u5) );
        op_reg( ops[2], REG_V(s5) );
        return Hex_vcombine;
    }
    if( BITS(27:21) == 0b1111110 && BIT(13) == 1 && BITS(7:5) == 0b111 )
    {
        // Vd32.uh = vmpy(Vu32.uh,Vv32.uh):>>16
        op_reg( ops[0], REG_V(d5), REG_POST_UH );
        op_reg( ops[1], REG_V(u5), REG_POST_UH );
        op_reg( ops[2], REG_V(s5), REG_POST_UH );
        flags = IPO_RS16;
        return Hex_vmpy;
    }

    return 0;
}

static uint32_t iclass_1_HVX_v73( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0), code, f;

    if( BITS(27:21) == 0b1100100 && BIT(13) == 1 )
    {
        // Qd4 [*]= vcmp.gt(Vu32.bf,Vv32.bf)
        switch( BITS(7:2) )
        {
        case 0b001110: flags = CMP_GT | IAT_OR;  break;
        case 0b011110: flags = CMP_GT | IAT_ASS; break;
        case 0b110100: flags = CMP_GT | IAT_AND; break;
        case 0b111100: flags = CMP_GT | IAT_XOR; break;
        default: return 0;
        }
        op_reg( ops[0], REG_Q(BITS(1:0)) );
        op_reg( ops[1], REG_V(u5), REG_POST_BF );
        op_reg( ops[2], REG_V(s5), REG_POST_BF );
        return Hex_vcmp;
    }
    if( BITS(27:23) == 0b11010 && BIT(21) == 0 && BIT(13) == 1 )
    {
        // various .bf ops
        switch( (BIT(22) << 3) | BITS(7:5) )
        {
        case 0b0000: code = Hex_vmpy,  f = RP(SF, BF, BF) | DD, flags = IAT_ADD; break;
        case 0b1000: code = Hex_vmin,  f = RP(BF, BF, BF); break;
        case 0b1011: code = Hex_vcvt2, f = RP(BF, SF, SF); break;
        case 0b1100: code = Hex_vmpy,  f = RP(SF, BF, BF) | DD; break;
        case 0b1101: code = Hex_vsub,  f = RP(SF, BF, BF) | DD; break;
        case 0b1110: code = Hex_vadd,  f = RP(SF, BF, BF) | DD; break;
        case 0b1111: code = Hex_vmax,  f = RP(BF, BF, BF); break;
        default: return 0;
        }
        op_reg( ops[0], REG_V(d5), FLG_D(f) );
        op_reg( ops[1], REG_V(u5), FLG_S(f) );
        op_reg( ops[2], REG_V(s5), FLG_T(f) );
        return code;
    }
    if( BITS(27:16) == 0b111000000101 && BIT(13) == 1 )
    {
        // Vd32.{w|h|sf|hf} = Vu32.{w|h|sf|hf}
        switch( BITS(7:5) )
        {
        case 0b001: f = RP( W, SF, _); break;
        case 0b010: f = RP( H, HF, _); break;
        case 0b011: f = RP(SF,  W, _); break;
        case 0b100: f = RP(HF,  H, _); break;
        default: return 0;
        }
        op_reg( ops[0], REG_V(d5), FLG_D(f) );
        op_reg( ops[1], REG_V(u5), FLG_S(f) );
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_2_HVX( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0);
    uint32_t mu = BIT(13)? REG_M1 : REG_M0, p2 = BITS(12:11), mtype;
    bool     has_pred = BIT(23), mem_inc = BIT(24);
    int32_t  imm = mem_inc? SBITS(10:8) : (SBIT(13) << 3) | BITS(10:8);

    switch( BITS(27:24) )
    {
    case 0b1000: // vmem(Rt32+#Ii)
    case 0b1001: // vmem(Rx32++#Ii)
    case 0b1011: // vmem(Rx32++Mu2)
        if( BITS(25:24) == 0b11 && BITS(10:8) ||
            BITS(25:24) == 0b01 && BIT(13) ||
            !has_pred && p2 )
            break;

        mtype = MEM_V | (BIT(22)? MEM_NT : 0);
        if( (BITS(23:21) & 0b101) == 0b001 && BITS(7:5) == 0 )
        {
            // vmem(Rx32+...)[:nt] = Vs32
            if( !mem_inc) op_mem_ind( ops[0], mtype, REG_R(s5), imm );
            else          op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, mtype,
                                      REG_R(s5), imm, mu );
            op_reg( ops[1], REG_V(d5) );
            return Hex_mov;
        }
        if( (BITS(23:21) & 0b101) == 0b001 && BITS(7:3) == 0b00100 )
        {
            // vmem(Rx32+...)[:nt] = Os8.new
            if( !mem_inc) op_mem_ind( ops[0], mtype, REG_R(s5), imm );
            else          op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, mtype,
                                      REG_R(s5), imm, mu );
            op_reg( ops[1], new_value( BITS(2:0), true ), REG_POST_NEW );
            return Hex_mov;
        }
        if( (BITS(23:21) & 0b101) == 0b101 && BITS(7:6) == 0b01 &&
            (BIT(4) ^ BIT(22)) == 0 && (BIT(3) ^ BIT(5)) == 0 )
        {
            // if ([!]{Pv4|Qv4}) vmem(Rx32+...)[:nt] = Os8.new
            op_reg( ops[PRED_A], REG_P(p2), BIT(5)? REG_PRE_NOT : 0 );
            if( !mem_inc) op_mem_ind( ops[0], mtype, REG_R(s5), imm );
            else          op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, mtype,
                                      REG_R(s5), imm, mu );
            op_reg( ops[1], new_value( BITS(2:0), true ), REG_POST_NEW );
            flags = PRED_REG;
            return Hex_mov;
        }
        if( BIT(23) && BITS(7:6) == 0 )
        {
            // if ([!]{Pv4|Qv4}) vmem(Rx32+...)[:nt] = Vs32
            op_reg( ops[PRED_A], BIT(21)? REG_P(p2) : REG_Q(p2), BIT(5)? REG_PRE_NOT : 0 );
            if( !mem_inc) op_mem_ind( ops[0], mtype, REG_R(s5), imm );
            else          op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, mtype,
                                      REG_R(s5), imm, mu );
            op_reg( ops[1], REG_V(d5) );
            flags = PRED_REG;
            return Hex_mov;
        }
        if( (BITS(23:21) & 0b101) == 0b100 && IN_RANGE(BITS(7:5), 2, 7) )
        {
            // if ([!]Pv4) Vd32[.tmp|.cur] = vmem(Rx32+...)[:nt]
            static const uint8_t vdf[4] = { 0, 0, REG_POST_CUR, REG_POST_TMP };

            op_reg( ops[PRED_A], REG_P(p2), BIT(5)? REG_PRE_NOT : 0 );
            op_reg( ops[0], REG_V(d5), vdf[ BITS(7:6) ] );
            if( !mem_inc) op_mem_ind( ops[1], mtype, REG_R(s5), imm );
            else          op_mem_inc( ops[1], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, mtype,
                                      REG_R(s5), imm, mu );
            flags = PRED_REG;
            return Hex_mov;
        }
        if( (BITS(23:21) & 0b101) == 0b000 && BITS(7:5) <= 2 )
        {
            // Vd32[.tmp|.cur] = vmem(Rx32+...)[:nt]
            static const uint8_t vdf[] = { 0, REG_POST_CUR, REG_POST_TMP };

            op_reg( ops[0], REG_V(d5), vdf[ BITS(7:5) ] );
            if( !mem_inc) op_mem_ind( ops[1], mtype, REG_R(s5), imm );
            else          op_mem_inc( ops[1], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, mtype,
                                      REG_R(s5), imm, mu );
            return Hex_mov;
        }
        if( (BITS(23:21) & 0b110) == 0b000 && BITS(7:5) == 0b111 )
        {
            // Vd32 = vmemu(Rx32+...) or vmemu(Rx32+...) = Vs32
            if( !BIT(21) ) {
                op_reg( ops[0], REG_V(d5) );
                if( !mem_inc) op_mem_ind( ops[1], MEM_VU, REG_R(s5), imm );
                else          op_mem_inc( ops[1], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, MEM_VU,
                                          REG_R(s5), imm, mu );
            } else {
                if( !mem_inc) op_mem_ind( ops[0], MEM_VU, REG_R(s5), imm );
                else          op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, MEM_VU,
                                          REG_R(s5), imm, mu );
                op_reg( ops[1], REG_V(d5) );
            }
            return Hex_mov;
        }
        if( BITS(23:21) == 0b101 && BITS(7:6) == 0b11 )
        {
            // if ([!]Pv4) vmemu(Rx32+...) = Vs32
            op_reg( ops[PRED_A], REG_P(p2), BIT(5)? REG_PRE_NOT : 0 );
            if( !mem_inc) op_mem_ind( ops[0], MEM_VU, REG_R(s5), imm );
            else          op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, MEM_VU,
                                      REG_R(s5), imm, mu );
            op_reg( ops[1], REG_V(d5) );
            flags = PRED_REG;
            return Hex_mov;
        }
        if( BITS(23:21) == 0b001 && BITS(12:11) == 0 && BITS(7:0) == 0b00101000 )
        {
            // vmem(Rx32+...):scatter_release
            if( !mem_inc ) op_mem_ind( ops[0], MEM_V, REG_R(s5), imm );
            else           op_mem_inc( ops[0], BIT(25)? o_mem_inc_reg : o_mem_inc_imm, MEM_V,
                                       REG_R(s5), imm, mu );
            return Hex_vscatterrls;
        }
        break;

    case 0b1111:
        if( BITS(23:21) == 0b000 && BITS(12:11) == 0 && BITS(9:8) != 3 && BIT(7) == 0 )
        {
            // [if (Qs4)] vtmp.{w|h} = vgather(Rt32,Mu2,Vv32.{w|h}).{w|h}
            uint32_t s2 = BITS(6:5);
            if( BIT(10) ) op_reg( ops[PRED_A], REG_Q(s2) );
            else if( s2 ) return 0;
            op_reg( ops[0], REG_VTMP, BITS(9:8)? REG_POST_H : REG_POST_W );
            op_reg( ops[1], REG_R(s5) );
            op_reg( ops[2], mu );
            op_reg( ops[3], REG_V(d5), BIT(8)? REG_POST_H : (REG_POST_W |
                                       (BIT(9)? REG_DOUBLE : 0)) );
            flags = (BIT(10)? PRED_REG : 0) | (BITS(9:8)? SG_H : SG_W);
            return Hex_vgather;
        }
        if( BITS(23:21) == 0b001 && BITS(6:5) != 3 )
        {
            // vscatter(Rt32,Mu2,Vvv32.{w|h}).{w|h} [+]= Vw32
            op_reg( ops[0], REG_R(s5) );
            op_reg( ops[1], mu );
            op_reg( ops[2], REG_V(u5), BIT(5)? REG_POST_H : (REG_POST_W |
                                       (BIT(6)? REG_DOUBLE : 0)) );
            op_reg( ops[3], REG_V(d5) );
            flags = (BITS(6:5)? SG_H : SG_W) | (BIT(7)? IAT_ADD : 0);
            return Hex_vscatter;
        }
        if( BITS(23:22) == 0b10 && (BIT(21) & BIT(7)) != 1 )
        {
            // if (Qs4) vscatter(Rt32,Mu2,Vvv32.{w|h}).{w|h} = Vw32
            op_reg( ops[PRED_A], REG_Q(BITS(6:5)) );
            op_reg( ops[0], REG_R(s5) );
            op_reg( ops[1], mu );
            op_reg( ops[2], REG_V(u5), BIT(7)? REG_POST_H : (REG_POST_W |
                                       (BIT(21)? REG_DOUBLE : 0)) );
            op_reg( ops[3], REG_V(d5) );
            flags = PRED_REG | ((BIT(21) | BIT(7))? SG_H : SG_W);
            return Hex_vscatter;
        }
        break;
    }
    return 0;
}

static uint32_t iclass_2_ZReg( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    bool     has_pred = BIT(23), mem_inc = BIT(24), reg = BIT(0);
    uint32_t s5 = BITS(20:16), mu = BIT(13)? REG_M1 : REG_M0, p2 = BITS(12:11);
    int32_t  imm = mem_inc? SBITS(10:8) : (SBIT(13) << 3) | BITS(10:8);

    if( (BITS(27:21) & 0b1110011) == 0b1100000 && BITS(7:1) == 0 )
    {
        // [if (Pv4)] z = vmem(Rt32+#Ii) or vmem(Rx32++{Mu2|#Ii})
        if( !has_pred && p2 || !mem_inc && reg ||
            mem_inc && reg && BITS(10:8) || mem_inc && !reg && BIT(13) )
            return 0;

        if( has_pred )
        {
            op_reg( ops[PRED_A], REG_P(p2) );
            flags = PRED_REG;
        }
        op_reg( ops[0], REG_Z );
        if( !mem_inc ) op_mem_ind( ops[1], MEM_V, REG_R(s5), imm );
        else           op_mem_inc( ops[1], reg? o_mem_inc_reg : o_mem_inc_imm, MEM_V,
                                   REG_R(s5), imm, mu );
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_9_HVX( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    uint32_t s5 = BITS(20:16), u5 = BITS(12:8), d5 = BITS(4:0);

    if( BITS(27:21) == 0b0010000 && BIT(13) == 0 && BITS(7:5) == 0b001 )
    {
        // Rd32 = vextract(Vu32,Rs32)
        op_reg( ops[0], REG_R(d5) );
        op_reg( ops[1], REG_V(u5) );
        op_reg( ops[2], REG_R(s5) );
        return Hex_vextract;
    }
    return 0;
}

//
// HMX instructions parsing
//

static uint32_t iclass_9_HMX( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    if( BITS(27:21) != 0b0010000 )
        return 0;

    uint32_t s5 = BITS(20:16), t5 = BITS(12:8);
    if( BIT(13) == 1 && BITS(7:5) == 0b010 )
    {
        // weight.n = mxmem(Rs32,Rt32):2x:...
        uint32_t suff;
        switch( BITS(4:0) )
        {
        case 0b00001: suff = MX_SINGLE; break;
        case 0b00010: suff = MX_DROP; break;
        case 0b00011: suff = MX_DEEP; break;
        case 0b00100: suff = MX_DILATE; break;
        case 0b00101: suff = MX_AFTER; break;
        case 0b00110: suff = 0; break;
        default: return 0;
        }
        op_reg( ops[0], REG_WEIGHT, REG_POST_N );
        op_mxmem( ops[1], MX_2X | suff, REG_R(s5), REG_R(t5) );
        return Hex_mov;
    }
    if( BITS(7:6) == 0b11 )
    {
        if( BIT(13) == 0 && t5 == 3 && BITS(5:1) == 0b11111 )
        {
            // bias = mxmem[2](Rs32)
            op_reg( ops[0], REG_BIAS );
            op_mxmem( ops[1], BIT(0)? 0 : MX_MEM2, REG_R(s5) );
            return Hex_mov;
        }
        if( BIT(13) == 0 && BIT(5) == 1 )
        {
            // activation.{ub|hf} = mxmem(Rs32,Rt32):...
            uint32_t suff, ub;
            switch( BITS(4:0) )
            {
            case 0b00000: ub = 1, suff = MX_DEEP; break;
            case 0b00001: ub = 1, suff = MX_DEEP | MX_CM; break;
            case 0b00010: ub = 0, suff = MX_DEEP; break;
            case 0b00100: ub = 0, suff = 0; break;
            case 0b00110: ub = 0, suff = MX_ABOVE; break;
            case 0b01000: ub = 1, suff = MX_DILATE; break;
            case 0b01001: ub = 1, suff = MX_DILATE | MX_CM; break;
            case 0b01100: ub = 1, suff = 0; break;
            case 0b01101: ub = 1, suff = MX_CM; break;
            case 0b01110: ub = 1, suff = MX_ABOVE; break;
            case 0b01111: ub = 1, suff = MX_ABOVE | MX_CM; break;
            case 0b10000: ub = 1, suff = MX_SINGLE; break;
            case 0b10001: ub = 1, suff = MX_SINGLE | MX_CM; break;
            case 0b11000: ub = 0, suff = MX_SINGLE; break;
            case 0b11010: ub = 0, suff = MX_DILATE; break;
            default: return 0;
            }
            op_reg( ops[0], REG_ACTIVATION, ub? REG_POST_UB : REG_POST_HF );
            op_mxmem( ops[1], suff, REG_R(s5), REG_R(t5) );
            return Hex_mov;
        }
        if( BIT(13) == 1 )
        {
            // weight.{sc|ubit|sbit|sm|b|n|c|hf} = mxmem(Rs32,Rt32):...
            uint32_t suff = 0, dt;
            switch( BITS(5:0) )
            {
            case 0b000000: dt = REG_POST_SC,   suff = MX_SINGLE; break;
            case 0b000001: dt = REG_POST_SC,   suff = MX_DROP; break;
            case 0b000010: dt = REG_POST_SC,   suff = MX_DEEP; break;
            case 0b000011: dt = REG_POST_SC,   suff = MX_AFTER; break;
            case 0b000100: dt = REG_POST_SC,   suff = MX_DILATE; break;
            case 0b000101: dt = REG_POST_UBIT, suff = MX_SINGLE; break;
            case 0b000110: dt = REG_POST_UBIT, suff = MX_DROP; break;
            case 0b000111: dt = REG_POST_UBIT, suff = MX_DEEP; break;
            case 0b001000: dt = REG_POST_UBIT, suff = MX_AFTER; break;
            case 0b001001: dt = REG_POST_UBIT, suff = MX_DILATE; break;
            case 0b001010: dt = REG_POST_SBIT, suff = MX_SINGLE; break;
            case 0b001011: dt = REG_POST_SBIT, suff = MX_DROP; break;
            case 0b001100: dt = REG_POST_SBIT, suff = MX_DEEP; break;
            case 0b001101: dt = REG_POST_SBIT, suff = MX_AFTER; break;
            case 0b001110: dt = REG_POST_SBIT, suff = MX_DILATE; break;
            case 0b001111: dt = REG_POST_SM,   suff = MX_SINGLE; break;
            case 0b010000: dt = REG_POST_SM,   suff = MX_DROP; break;
            case 0b010001: dt = REG_POST_SM,   suff = MX_DEEP; break;
            case 0b010010: dt = REG_POST_SM,   suff = MX_AFTER; break;
            case 0b010011: dt = REG_POST_SM,   suff = MX_DILATE; break;
            case 0b100000: dt = REG_POST_B;    break;
            case 0b100001: dt = REG_POST_N;    break;
            case 0b100010: dt = REG_POST_C;    break;
            case 0b100011: dt = REG_POST_UBIT; break;
            case 0b100100: dt = REG_POST_SBIT; break;
            case 0b100110: dt = REG_POST_B,    suff = MX_SINGLE; break;
            case 0b100111: dt = REG_POST_B,    suff = MX_DROP; break;
            case 0b101000: dt = REG_POST_B,    suff = MX_DEEP; break;
            case 0b101001: dt = REG_POST_B,    suff = MX_AFTER; break;
            case 0b101011: dt = REG_POST_B,    suff = MX_DILATE; break;
            case 0b101100: dt = REG_POST_N,    suff = MX_SINGLE; break;
            case 0b101101: dt = REG_POST_N,    suff = MX_DROP; break;
            case 0b101110: dt = REG_POST_N,    suff = MX_DEEP; break;
            case 0b101111: dt = REG_POST_HF;   break;
            case 0b110000: dt = REG_POST_SC;   break;
            case 0b110001: dt = REG_POST_SM;   break;
            case 0b110010: dt = REG_POST_HF,   suff = MX_SINGLE; break;
            case 0b110011: dt = REG_POST_HF,   suff = MX_DROP; break;
            case 0b110100: dt = REG_POST_HF,   suff = MX_DEEP; break;
            case 0b110101: dt = REG_POST_HF,   suff = MX_AFTER; break;
            case 0b110110: dt = REG_POST_HF,   suff = MX_DILATE; break;
            case 0b110111: dt = REG_POST_N,    suff = MX_AFTER; break;
            case 0b111000: dt = REG_POST_N,    suff = MX_DILATE; break;
            case 0b111001: dt = REG_POST_C,    suff = MX_SINGLE; break;
            case 0b111010: dt = REG_POST_C,    suff = MX_DROP; break;
            case 0b111011: dt = REG_POST_C,    suff = MX_DEEP; break;
            case 0b111100: dt = REG_POST_C,    suff = MX_AFTER; break;
            case 0b111101: dt = REG_POST_C,    suff = MX_DILATE; break;
            default: return 0;
            }
            op_reg( ops[0], REG_WEIGHT, dt );
            op_mxmem( ops[1], suff, REG_R(s5), REG_R(t5) );
            return Hex_mov;
        }
    }
    return 0;
}

static uint32_t iclass_10_HMX( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    if( BITS(27:21) != 0b0110111 || BITS(7:5) != 0 )
        return 0;

    uint32_t s5 = BITS(20:16), t5 = BITS(12:8);
    if( BIT(13) == 0 && BIT(4) == 0 )
    {
        // mxmem(Rs32,Rt32):{before|after}[:retain][:cm][:sat}.ub=acc
        op_mxmem( ops[0], MX_UB |
                           (BIT(0)? MX_CM : 0) |
                           (BIT(1)? 0 : MX_SAT) |
                           (BIT(2)? MX_AFTER : MX_BEFORE) |
                           (BIT(3)? MX_RETAIN : 0), REG_R(s5), REG_R(t5) );
        op_acc( ops[1] );
        return Hex_mov;
    }
    if( BIT(13) == 1 && BIT(4) == 0 )
    {
        // mxmem(Rs32,Rt32):{before|after}[:retain][:{pos|sat}].{uh|hf}=acc[:2x1]
        static const uint32_t suff[16] = {
            MX_BEFORE, MX_BEFORE | MX_POS, MX_BEFORE | MX_SAT, MX_BEFORE,
            MX_AFTER, MX_BEFORE | MX_RETAIN | MX_POS, MX_BEFORE | MX_RETAIN | MX_SAT, MX_BEFORE | MX_RETAIN,
            MX_BEFORE | MX_RETAIN, MX_AFTER | MX_POS, MX_AFTER | MX_SAT, MX_AFTER,
            MX_AFTER | MX_RETAIN, MX_AFTER | MX_RETAIN | MX_POS, MX_AFTER | MX_RETAIN | MX_SAT, MX_AFTER | MX_RETAIN,
        };
        op_mxmem( ops[0], suff[ BITS(3:0) ] |
                           (BIT(1)? MX_UH : MX_HF),
                           REG_R(s5), REG_R(t5) );
        op_acc( ops[1], BIT(1)? ACC_2X1 : 0 );
        return Hex_mov;
    }
    if( BIT(13) == 1 && BIT(4) == 1 && BIT(1) == 1 )
    {
        // mxmem(Rs32,Rt32):{before|after}[:retain][:sat].uh=acc:2x2
        op_mxmem( ops[0], MX_UH |
                           (BIT(3)? MX_AFTER : MX_BEFORE) |
                           (BIT(2)? MX_RETAIN : 0) |
                           (BIT(0)? 0 : MX_SAT),
                           REG_R(s5), REG_R(t5) );
        op_acc( ops[1], ACC_2X2 );
        return Hex_mov;
    }
    // rest of instructions
    if( BITS(13:8) == 0 && BITS(4:3) == 0b10 )
    {
        switch( BITS(2:0) )
        {
        case 0b000:
        case 0b110:
            // mxmem[2](Rs32)=bias
            op_mxmem( ops[0], BIT(1)? MX_MEM2 : 0, REG_R(s5) );
            op_reg( ops[1], REG_BIAS );
            return Hex_mov;
        case 0b001:
        case 0b011:
            // mxclracc[.hf]
            if( s5 ) return 0;
            op_acc( ops[0], BIT(1)? ACC_HF : 0 );
            return Hex_mxclr;
        case 0b100:
        case 0b101:
            // mxswapacc[.hf]
            if( s5 ) return 0;
            op_acc( ops[0], BIT(0)? ACC_HF : 0 );
            return Hex_mxswap;
        case 0b111:
            // acc=mxshl(acc,#16)
            op_acc( ops[0] );
            op_imm( ops[1], 16 );
            return Hex_mxshl;
        }
    }
    if( BIT(13) == 0 && BITS(4:0) == 0b10000 )
    {
        // cvt.{ub|uh|hf} = acc(Rs32)[:2x1|:2x2|:sc0|:sc1]
        uint32_t dt, suff;
        switch( BITS(12:8) )
        {
        case 0b10111: dt = REG_POST_UB, suff = 0; break;
        case 0b11000: dt = REG_POST_UH, suff = ACC_2X1; break;
        case 0b11001: dt = REG_POST_UH, suff = ACC_2X2; break;
        case 0b11010: dt = REG_POST_HF, suff = 0; break;
        case 0b11100: dt = REG_POST_UB, suff = ACC_SC0; break;
        case 0b11101: dt = REG_POST_UB, suff = ACC_SC1; break;
        default: return 0;
        }
        op_reg( ops[0], REG_CVT, dt );
        op_acc( ops[1], suff, REG_R(s5) );
        return Hex_mov;
    }
    if( BIT(13) == 0 && BITS(4:2) == 0b110 && BITS(1:0) != 3 )
    {
        // mxmem(Rs32,Rt32)[:cm|:2x2] = cvt
        static const uint32_t suff[3] = { 0, MX_CM, MX_2X2 };
        op_mxmem( ops[0], suff[ BITS(1:0) ], REG_R(s5), REG_R(t5) );
        op_reg( ops[1], REG_CVT );
        return Hex_mov;
    }
    return 0;
}

//
// DMA instructions parsing
//

static uint32_t iclass_9_DMA( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &/*flags*/ )
{
    if( BITS(27:21) == 0b0010000 && BIT(13) == 0 && BITS(11:5) == 0b1000000 )
    {
        // Rd[d]32 = memX_aq(Rs32)
        uint32_t s5 = BITS(20:16), d5 = BITS(4:0);
        op_reg( ops[0], REG_R(d5), BIT(12)? REG_DOUBLE : 0 );
        op_mem_ind( ops[1], MEM_AQ | (BIT(12)? MEM_D : MEM_W), REG_R(s5), 0 );
        return Hex_mov;
    }
    return 0;
}

static uint32_t iclass_10_DMA( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    if( BIT(13) != 0 ) return 0;
    uint32_t s5 = BITS(20:16), t5 = BITS(12:8), d5 = BITS(4:0);

    if( BITS(24:21) == 0 )
    {
        switch( (BITS(27:25) << 3) | BITS(7:5) )
        {
        case 0b011001:
        case 0b011100:
            if( t5 == 0 && d5 == 0 ) {
                // dmstart(Rs32) / dmresume(Rs32)
                op_reg( ops[0], REG_R(s5) );
                return BIT(5)? Hex_dmstart : Hex_dmresume;
            }
            break;

        case 0b011010:
            if( d5 == 0 ) {
                // dmlink(Rs32,Rt32)
                op_reg( ops[0], REG_R(s5) );
                op_reg( ops[1], REG_R(t5) );
                return Hex_dmlink;
            }
            break;

        case 0b100001:
        case 0b100010:
        case 0b100011:
            if( s5 == 0 && t5 == 0 ) {
                // Rd32 = {dmwait,dmpoll,dmpause}
                op_reg( ops[0], REG_R(d5) );
                return BITS(6:5) == 1? Hex_dmwait : BITS(6:5) == 2? Hex_dmpoll : Hex_dmpause;
            }
            break;

        case 0b100101:
            if( t5 == 0 ) {
                // Rd32 = dmcfgrd(Rs32)
                op_reg( ops[0], REG_R(d5) );
                op_reg( ops[1], REG_R(s5) );
                return Hex_dmcfgrd;
            }
            break;

        case 0b100110:
            if( d5 == 0 ) {
                // dmcfgwr(Rs32,Rt32)
                op_reg( ops[0], REG_R(s5) );
                op_reg( ops[1], REG_R(t5) );
                return Hex_dmcfgwr;
            }
            break;

        case 0b100111:
            if( s5 == 0 && BITS(12:9) == 0 ) {
                // Rd32 = {dmsyncht,dmtlbsynch}
                op_reg( ops[0], REG_R(d5) );
                return BIT(8)? Hex_dmtlbsynch : Hex_dmsyncht;
            }
            break;
        }
    }
    else if( (BITS(27:21) & 0b1111101) == 0b0000101 && (BITS(7:0) & 0b11011111) == 0b00001000 )
    {
        // memX_rl(Rs32):{at,st} = Rt[t]32
        op_mem_ind( ops[0], MEM_RL |
                            (BIT(22)? MEM_D : MEM_W) |
                            (BIT(5)? MEM_ST : MEM_AT), REG_R(s5), 0 );
        op_reg( ops[1], REG_R(t5), BIT(22)? REG_DOUBLE : 0 );
        return Hex_mov;
    }
    else if( BITS(27:21) == 0b0000111 && t5 == 0 && (BITS(7:0) & 0b11011111) == 0b00001100 )
    {
        // release(Rs32):{at,st}
        op_reg( ops[0], REG_R(s5) );
        flags = BIT(5)? IPO_ST : IPO_AT;
        return Hex_release;
    }
    return 0;
}

static void simplify( insn_t &insn )
{
    op_t *ops = insn.ops;

    switch( insn.itype )
    {
    case Hex_sub:
        if( ops[2].is_imm(0) )
        {
            // Rd32 = sub(#0, Rs32)  -->  Rd32 = neg(Rs32)
            insn.itype = Hex_neg;
        }
        else if( ops[2].is_imm(-1) )
        {
            // Rd32 = sub(#-1, Rs32)  -->  Rd32 = not(Rs32)
            insn.itype = Hex_not;
        }
        break;

    case Hex_trap1_2:
        if( ops[0].is_reg( REG_R0 ) )
        {
            // trap1(r0,#Ii) --> trap1(#Ii)
            ops[0] = ops[1];
            insn.itype = Hex_trap1;
        }
        break;

    case Hex_combine:
        {
            op_t &op1 = ops[1], &op2 = ops[2];
            if( ops[0].specval == REG_DOUBLE &&
                op1.type == o_reg && op2.type == o_reg &&
                op1.reg == op2.reg + 1 && ((op1.reg - REG_R0) & 1) )
            {
                // Rdd32 = combine(Rss32.h, Rss32.l)  -->  Rdd32 = Rss32
                op1.reg--;
                op1.specval = REG_DOUBLE;
                insn.itype = Hex_mov;
            }
            else if( ops[0].specval == REG_DOUBLE &&
                     op1.type == o_imm && op2.type == o_imm && !(op2.specflag1 & IMM_EXTENDED) &&
                     (op1.value == 0 && op2.value < 0x80000000 ||
                      op1.value == -1 && op2.value >= 0x80000000) )
            {
                // Rdd32 = combine(#{0|-1}, #s8)  -->  Rdd32 = #Ii
                op1 = op2;
                insn.itype = Hex_mov;
            }
        }
        break;

    case Hex_add:
        if( ops[2].is_imm( 0 ) && !(ops[2].specflag1 & IMM_EXTENDED) )
        {
            // Rd32 = add(Rs32, #0)  -->  Rd32 = Rs32
            insn.itype = Hex_mov;
        }
        break;

    case Hex_and:
        if( ops[2].is_imm( 0xFF ) )
        {
            // Rd32 = and(Rs32, #255)  -->  Rd32 = zxtb(Rs32)
            insn.itype = Hex_zxtb;
        }
        break;

    case Hex_or:
        if( IN_RANGE( ops[0].reg, REG_P0, REG_P0 + 3 ) &&
            ops[1].reg == ops[2].reg && ops[2].specval == 0 )
        {
            // Pd4 = or(Ps4,Ps4)  -->  Pd4 = Ps4
            insn.itype = Hex_mov;
        }
        break;

    case Hex_vxor:
        if( ops[1].reg == ops[2].reg )
        {
            // Vd32 = vxor(Vd32,Vd32) --> Vd32 = #0
            ops[1].type = o_imm;
            ops[1].value = 0;
            ops[1].dtype = dt_dword;
            insn.itype = Hex_mov;
        }
        break;

    case Hex_vsub:
        if( (reg_op_flags( ops[0] ) & REG_DOUBLE) && ops[1].reg == ops[2].reg &&
            (insn_flags( insn ) >> 4) == 0 )
        {
            // Vdd32.w = vsub(Vdd32.w, Vdd32.w) --> Vdd32 = #0
            ops[0].specval = REG_DOUBLE; // remove postfix
            ops[1].type = o_imm;
            ops[1].value = 0;
            ops[1].dtype = dt_dword;
            insn.itype = Hex_mov;
        }
        break;

    case Hex_vcombine:
        {
            op_t &op1 = ops[1], &op2 = ops[2];
            if( op1.reg == op2.reg + 1 )
            {
                // Vdd32 = combine(Vss32.h, Vss32.l)  -->  Vdd32 = Vss32
                op1.reg--;
                op1.specval = REG_DOUBLE;
                insn.itype = Hex_mov;
            }
        }
        break;
    }
}

static bool decode_single( insn_t &insn, uint32_t word, uint64_t extender )
{
    uint32_t iclass = BITS(31:28);
    uint32_t itype = 0, flags = 0;
    op_t *ops = insn.ops;

    switch( iclass )
    {
    case 1:
        itype = iclass_1_CJ( word, extender, ops, flags );
        if( !itype ) itype = iclass_1_HVX( word, extender, ops, flags );
        if( !itype ) itype = iclass_1_ZReg( word, extender, ops, flags );
        if( !itype ) itype = iclass_1_HVX_v68( word, extender, ops, flags );
        if( !itype ) itype = iclass_1_HVX_v69( word, extender, ops, flags );
        if( !itype ) itype = iclass_1_HVX_v73( word, extender, ops, flags );
        break;
    case 2:
        itype = iclass_2_NCJ( word, extender, ops, flags );
        if( !itype ) itype = iclass_2_HVX( word, extender, ops, flags );
        if( !itype ) itype = iclass_2_ZReg( word, extender, ops, flags );
        break;
    case 3:
        itype = iclass_3_V4LDST( word, extender, ops, flags );
        break;
    case 4:
        itype = iclass_4_V2LDST( word, extender, ops, flags );
        break;
    case 5:
        itype = iclass_5_J( word, extender, ops, flags );
        if( !itype ) itype = iclass_5_SYS( word, extender, ops, flags );
        break;
    case 6:
        itype = iclass_6_CR( word, extender, ops, flags );
        if( !itype ) itype = iclass_6_SYS( word, extender, ops, flags );
        break;
    case 7:
        itype = iclass_7_ALU2op( word, extender, ops, flags );
        break;
    case 8:
        itype = iclass_8_S2op( word, extender, ops, flags );
        break;
    case 9:
        itype = iclass_9_LD( word, extender, ops, flags );
        if( !itype ) itype = iclass_9_LD_EXT( word, extender, ops, flags );
        if( !itype ) itype = iclass_9_HVX( word, extender, ops, flags );
        if( !itype ) itype = iclass_9_HMX( word, extender, ops, flags );
        if( !itype ) itype = iclass_9_DMA( word, extender, ops, flags );
        break;
    case 10:
        itype = iclass_10_ST( word, extender, ops, flags );
        if( !itype ) itype = iclass_10_ST_EXT( word, extender, ops, flags );
        if( !itype ) itype = iclass_10_SYS( word, extender, ops, flags );
        if( !itype ) itype = iclass_10_HMX( word, extender, ops, flags );
        if( !itype ) itype = iclass_10_DMA( word, extender, ops, flags );
        break;
    case 11:
        itype = iclass_11_ADDI( word, extender, ops, flags );
        break;
    case 12:
        itype = iclass_12_S3op( word, extender, ops, flags );
        break;
    case 13:
        itype = iclass_13_ALU64( word, extender, ops, flags );
        break;
    case 14:
        itype = iclass_14_M( word, extender, ops, flags );
        break;
    case 15:
        itype = iclass_15_ALU3op( word, extender, ops, flags );
        break;
    }

    if( !itype ) return false;
    insn.itype = itype;
    insn.auxpref = flags;
    // simplify instruction if possible
    simplify( insn );
    return true;
}

//
// duplex instructions parsing
//

static __inline uint8_t duplex_dreg( uint32_t v )
{
    assert( v < 8 );
    return REG_R( 2*v + (v < 4? 0 : 8) );
};

static uint8_t duplex_L1( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t& )
{
    // Rd16 = mem[ub|w](Rs16+#Ii)
    bool memub = BITS(12:12) != 0;
    op_reg( ops[0], gen_sub_reg( BITS(3:0) ) );
    op_mem_ind( ops[1],
        memub? MEM_UB : MEM_W,
        gen_sub_reg( BITS(7:4) ),
        BITS(11:8) << (memub? 0 : 2)
    );
    return Hex_mov;
}

static uint8_t duplex_S1( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t& )
{
    // mem[b|w](Rs16+#Ii) = Rt16
    bool memb = BITS(12:12) != 0;
    op_mem_ind( ops[0],
        memb? MEM_B : MEM_W,
        gen_sub_reg( BITS(7:4) ),
        BITS(11:8) << (memb? 0 : 2)
    );
    op_reg( ops[1], gen_sub_reg( BITS(3:0) ) );
    return Hex_mov;
}

static uint8_t duplex_L2( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t &flags )
{
    uint32_t target = BITS(12:11);
    if( target != 3 )
    {
        // Rd16 = mem[h|uh|b](Rs16+#Ii)
        op_reg( ops[0], gen_sub_reg( BITS(3:0) ) );
        op_mem_ind( ops[1],
            target == 0? MEM_H : target == 1? MEM_UH : MEM_B,
            gen_sub_reg( BITS(7:4) ),
            BITS(10:8) << (target == 2? 0 : 1)
        );
        return Hex_mov;
    }
    if( BITS(10:9) == 0b10 )
    {
        // Rd16 = memw(r29+#Ii)
        op_reg( ops[0], gen_sub_reg( BITS(3:0) ) );
        op_mem_ind( ops[1],
            MEM_W,
            REG_SP,
            BITS(8:4) << 2
        );
        return Hex_mov;
    }
    if( BITS(10:8) == 0b110 )
    {
        // Rdd8 = memd(r29+#Ii)
        op_reg( ops[0], duplex_dreg( BITS(2:0) ), REG_DOUBLE );
        op_mem_ind( ops[1],
            MEM_D,
            REG_SP,
            BITS(7:3) << 3
        );
        return Hex_mov;
    }
    if( word == 0b1111100000000 ) return Hex_deallocframe;
    if( word == 0b1111101000000 ) return Hex_return;
    if( BITS(12:2) == 0b11111010001 )
    {
        // if ([!]p0[.new]) dealloc_return[:nt]
        uint32_t reg_flags = ((word & 1)? REG_PRE_NOT : 0) |
                             ((word & 2)? REG_POST_NEW : 0);
        op_reg( ops[PRED_A], REG_P0, reg_flags );
        flags = PRED_REG | ((word & 2)? JMP_NT : 0);
        return Hex_return;
    }
    if( word == 0b1111111000000 )
    {
        // jumpr r31
        op_reg( ops[0], REG_LR );
        return Hex_jumpr;
    }
    if( BITS(12:2) == 0b11111110001 )
    {
        // if ([!]p0[.new]) jumpr[:nt] r31
        uint32_t reg_flags = ((word & 1)? REG_PRE_NOT : 0) |
                             ((word & 2)? REG_POST_NEW : 0);
        op_reg( ops[PRED_A], REG_P0, reg_flags );
        op_reg( ops[0], REG_LR );
        flags = PRED_REG | ((word & 2)? JMP_NT : 0);
        return Hex_jumpr;
    }
    return 0;
}

static uint8_t duplex_S2( uint32_t word, uint64_t /*extender*/, op_t *ops, uint32_t& )
{
    if( BITS(12:11) == 0b00 )
    {
        // memh(Rs16+#Ii) = Rt16
        op_mem_ind( ops[0],
            MEM_H,
            gen_sub_reg( BITS(7:4) ),
            BITS(10:8) << 1
        );
        op_reg( ops[1], gen_sub_reg( BITS(3:0) ) );
        return Hex_mov;
    }
    if( BITS(12:9) == 0b0100 )
    {
        // memw(r29+#Ii) = Rt16
        op_mem_ind( ops[0],
            MEM_W,
            REG_SP,
            BITS(8:4) << 2
        );
        op_reg( ops[1], gen_sub_reg( BITS(3:0) ) );
        return Hex_mov;
    }
    if( BITS(12:9) == 0b0101 )
    {
        // memd(r29+#Ii) = Rtt8
        op_mem_ind( ops[0],
            MEM_D,
            REG_SP,
            SBITS(8:3) << 3
        );
        op_reg( ops[1], duplex_dreg( BITS(2:0) ), REG_DOUBLE );
        return Hex_mov;
    }
    if( BITS(12:10) == 0b100 )
    {
        // mem[b|w](Rs16+#Ii) = #[0|1]
        bool memb = BIT(9) != 0;
        op_mem_ind( ops[0],
            memb? MEM_B : MEM_W,
            gen_sub_reg( BITS(7:4) ),
            BITS(3:0) << (memb? 0 : 2)
        );
        op_imm( ops[1], BIT(8) );
        return Hex_mov;
    }
    if( BITS(12:9) == 0b1110 && BITS(3:0) == 0b0000 )
    {
        // allocframe(#Ii)
        op_imm( ops[0], BITS(8:4) << 3 );
        return Hex_allocframe;
    }
    return 0;
}

static uint8_t duplex_A( uint32_t word, uint64_t extender, op_t *ops, uint32_t &flags )
{
    uint32_t s4 = BITS(7:4), d4 = BITS(3:0);
    bool extended = extender != 0;

    if( BITS(12:11) == 0b00 )
    {
        // Rx16 = add(Rx16in,#Ii) [EXT]
        uint32_t rx = gen_sub_reg( d4 );
        op_reg( ops[0], rx );
        op_reg( ops[1], rx );
        op_imm( ops[2], EXTEND( SBITS(10:4), 0 ), true, extended );
        return Hex_add;
    }
    if( BITS(12:10) == 0b010 )
    {
        // Rd16 = #Ii [EXT]
        op_reg( ops[0], gen_sub_reg( d4 ) );
        op_imm( ops[1], EXTEND( BITS(9:4), 0 ), false, extended );
        return Hex_mov;
    }
    if( BITS(12:10) == 0b011 )
    {
        // Rd16 = add(r29,#Ii)
        op_reg( ops[0], gen_sub_reg( d4 ) );
        op_reg( ops[1], REG_SP );
        op_imm( ops[2], BITS(9:4) << 2 );
        return Hex_add;
    }
    if( BITS(12:11) == 0b10 )
    {
        op_reg( ops[0], gen_sub_reg( d4 ) );
        op_reg( ops[1], gen_sub_reg( s4 ) );
        switch( BITS(10:8) )
        {
        case 0: return Hex_mov;  // Rd16 = Rs16
        case 1: op_imm( ops[2], 1 );
                return Hex_add;  // Rd16 = add(Rs16,#1)
        case 2: op_imm( ops[2], 1 );
                return Hex_and;  // Rd16 = and(Rs16,#1)
        case 3: op_imm( ops[2], -1, true );
                return Hex_add;  // Rd16 = add(Rs16,#n1)
        case 4: return Hex_sxth; // Rd16 = sxth(Rs16)
        case 5: return Hex_sxtb; // Rd16 = sxtb(Rs16)
        case 6: return Hex_zxth; // Rd16 = zxth(Rs16)
        case 7: return Hex_zxtb; // Rd16 = zxtb(Rs16)
        }
    }
    if( BITS(12:8) == 0b11000 )
    {
        // Rx16 = add(Rx16in,Rs16)
        uint32_t rx = gen_sub_reg( d4 );
        op_reg( ops[0], rx );
        op_reg( ops[1], rx );
        op_reg( ops[2], gen_sub_reg( s4 ) );
        return Hex_add;
    }
    if( BITS(12:8) == 0b11001 && BITS(3:2) == 0b00 )
    {
        // p0 = cmp.eq(Rs16,#Ii)
        op_reg( ops[0], REG_P0 );
        op_reg( ops[1], gen_sub_reg( s4 ) );
        op_imm( ops[2], d4 );
        flags = CMP_EQ;
        return Hex_cmp;
    }
    if( BITS(12:4) == 0b110100000 )
    {
        // Rd16 = #n1
        op_reg( ops[0], gen_sub_reg( d4 ) );
        op_imm( ops[1], -1, true );
        return Hex_mov;
    }
    if( BITS(12:6) == 0b1101001 )
    {
        // if ([!]p0[.new]) Rd16 = #0
        op_reg( ops[PRED_A], REG_P0, (BIT(4)? REG_PRE_NOT : 0) |
                                     (BIT(5)? 0 : REG_POST_NEW) );
        op_reg( ops[0], gen_sub_reg( d4 ) );
        op_imm( ops[1], 0 );
        flags = PRED_REG;
        return Hex_mov;
    }
    if( BITS(12:7) == 0b111000 )
    {
        // Rdd8 = combine(#i,#Ii)
        op_reg( ops[0], duplex_dreg( BITS(2:0) ), REG_DOUBLE );
        if( BITS(4:3) == 0 ) {
            op_imm( ops[1], BITS(6:5) );
            return Hex_mov; // simplify
        }
        op_imm( ops[1], BITS(4:3) );
        op_imm( ops[2], BITS(6:5) );
        return Hex_combine;
    }
    if( BITS(12:8) == 0b11101 )
    {
        // Rdd8 = combine(Rs16,#0)
        uint32_t rs = gen_sub_reg( BITS(7:4) );
        op_reg( ops[0], duplex_dreg( BITS(2:0) ), REG_DOUBLE );
        if( BIT(3) == 0 ) {
            op_imm( ops[1], 0 );
            op_reg( ops[2], rs );
        } else {
            op_reg( ops[1], rs );
            op_imm( ops[2], 0 );
        }
        return Hex_combine;
    }
    return 0;
}

typedef uint8_t (*duplex_parser)( uint32_t, uint64_t, op_t*, uint32_t& );
static const duplex_parser dp[15][2] = {
    // class        low       high
    /*  0*/ { duplex_L1, duplex_L1 },
    /*  1*/ { duplex_L2, duplex_L1 },
    /*  2*/ { duplex_L2, duplex_L2 },
    /*  3*/ { duplex_A,  duplex_A  },
    /*  4*/ { duplex_L1, duplex_A  },
    /*  5*/ { duplex_L2, duplex_A  },
    /*  6*/ { duplex_S1, duplex_A  },
    /*  7*/ { duplex_S2, duplex_A  },
    /*  8*/ { duplex_S1, duplex_L1 },
    /*  9*/ { duplex_S1, duplex_L2 },
    /* 10*/ { duplex_S1, duplex_S1 },
    /* 11*/ { duplex_S2, duplex_S1 },
    /* 12*/ { duplex_S2, duplex_L1 },
    /* 13*/ { duplex_S2, duplex_L2 },
    /* 14*/ { duplex_S2, duplex_S2 },
};

static bool decode_duplex( insn_t &insn, uint32_t word, uint64_t extender )
{
    uint32_t dclass = (BITS(31:29) << 1) | BIT(13);
    uint32_t itype, flags = 0;
    op_t *ops = insn.ops;

    // duplex class 15 is reserved
    if( dclass == 15 ) return false;
    // TODO: check that other half is decodable as well
    if( (insn.ea & 2) == 0 )
    {
        // parse high sub-instruction
        itype = dp[dclass][1]( BITS(28:16), extender, ops, flags );
    }
    else
    {
        // parse low sub-instruction (w/o extender)
        itype = dp[dclass][0]( BITS(12:0), 0, ops, flags );
    }

    if( !itype ) return false;
    insn.itype = itype;
    insn.auxpref = flags;
    insn.flags |= INSN_DUPLEX;
    return true;
}

//
// analyze an instruction
//

ssize_t ana( insn_t &insn )
{
    ea_t ea = s_insn_ea = insn.ea;
    // instructions are always aligned on 4
    if( (ea & 1) )
        return 0;

    uint32_t word = get_dword( ea & ~2 );
    uint32_t parse = BITS(15:14), iclass = BITS(31:28);
    uint64_t extender = 0;

    // ... with the exception of 2nd word of duplex
    if( (ea & 2) && parse != PARSE_DUPLEX )
        return 0;

    // is it a constant extender?
    if( parse != PARSE_DUPLEX && iclass == 0 )
    {
        // extender cannot be the last insn in the packet
        if( parse == PARSE_LAST ) return 0;
        // use 32nd bit to distinguish between no extender and a zero extender
        extender = (1ull << 32) | (BITS(27:16) << 20) | (BITS(13:0) << 6);
        // extender always extends the next instruction, so lets absorb it
        insn.flags |= INSN_EXTENDED;
        // read next instruction
        word = get_dword( ea += 4 );
        parse = BITS(15:14);
    }

    // instructions are either 4 or 2 bytes long plus optional extender
    insn.size = (extender? 4 : 0) + (parse == PARSE_DUPLEX? 2 : 4);

    ea_t pkt_end;
    if( !find_packet_boundaries( ea, &s_pkt_start, &pkt_end ) )
        return 0;
    // set offsets (in bytes) to the packet start/end
    insn.segpref = insn.ea - s_pkt_start;
    insn.insnpref = pkt_end - insn.ea;
    // set packet flags
    if( insn.ea == s_pkt_start )
        insn.flags |= INSN_PKT_BEG;
    if( insn.ea + insn.size == pkt_end )
        insn.flags |= INSN_PKT_END | get_endloop( s_pkt_start );

    // decode instruction word
    bool decoded = (parse == PARSE_DUPLEX)?
        decode_duplex( insn, word, extender ) :
        decode_single( insn, word, extender );
    // if( !decoded )
    //     msg( "0x%03x: failed to decode - word = 0x%08x (ext=0x%llx)\n", insn.ea, word, extender );
    // return instruction size in bytes or 0
    return decoded? insn.size : 0;
}
