/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "common.h"

template <typename Visitor, typename ...Args>
static __inline bool visit_sub_insn( const insn_t &insn, Visitor visitor, Args... args )
{
    if( (insn.flags & INSN_DUPLEX) )
    {
        const op_t *ops = insn.ops;
        uint32_t itype = sub_insn_code( insn, 1 ), flags = insn_flags( insn, 1 );
        if( visitor( itype, flags, ops, args... ) )
            return true;
        ops += get_num_ops( itype, flags );
        itype = sub_insn_code( insn, 0 ), flags = insn_flags( insn, 0 );
        return visitor( itype, flags, ops, args... );
    }
    else
        return visitor( insn.itype, insn_flags( insn ), insn.ops, args... );
}

static bool is_ret_or_jump( const insn_t &insn )
{
    // returns true if it's an unconditional jump or return
    if( (insn.flags & INSN_DUPLEX) )
    {
        uint32_t ins_lo = sub_insn_code( insn, 0 ), ins_hi = sub_insn_code( insn, 1 );
        return (ins_lo == Hex_return || ins_lo == Hex_jumpr) && (insn_flags( insn, 0 ) & PRED_MASK) == 0 ||
               (ins_hi == Hex_return || ins_hi == Hex_jumpr) && (insn_flags( insn, 1 ) & PRED_MASK) == 0;
    }
    return (insn.itype == Hex_jump || insn.itype == Hex_jumpr || insn.itype == Hex_set_jump ||
            insn.itype == Hex_return_raw || insn.itype == Hex_return) &&
           (insn_flags( insn, 0 ) & PRED_MASK) == 0;
}

static bool is_basic_block_end( const insn_t &insn )
{
    static ea_t next_ea = BADADDR;
    static bool basic_block_end = false;

    // usually emu is called sequentially,
    // so we cheat and cache information from prevuos instructions
    if( insn.ea == next_ea || (insn.flags & INSN_PKT_BEG) )
    {
        if( (insn.flags & INSN_PKT_BEG) ) basic_block_end = false;
        basic_block_end |= is_ret_or_jump( insn );
        next_ea = insn.ea + insn.size;
        // don't split packet in the middle
        return (insn.flags & INSN_PKT_END) && basic_block_end;
    }
    // definitely not the end
    if( !(insn.flags & INSN_PKT_END) )
        return false;
    // otherwise scan all instructions in the packet
    bool res = is_ret_or_jump( insn );
    if( (insn.flags & INSN_PKT_BEG) == 0 )
    {
        ea_t ea = insn.ea;
        insn_t temp;
        do
        {
            ea = decode_prev_insn( &temp, ea );
            if( ea == BADADDR ) return false;
            res |= is_ret_or_jump( temp );
        } while( !(temp.flags & INSN_PKT_BEG) );
    }
    return res;
}

static void handle_insn( const insn_t &insn, uint32_t itype, uint32_t flags, const op_t *ops )
{
    func_t *pfn = get_func( insn.ea );
    flags_t F;

    switch( itype )
    {
    case Hex_allocframe:
        // trace modification of SP register
        // TODO: the actual SP change happens at the end of packet
        if( pfn && may_trace_sp() )
            add_auto_stkpnt( pfn, insn.ea + insn.size, -(ops[0].value + 8) );
        break;

    case Hex_add:
        ops += get_op_index( flags );
        F = get_flags( insn.ea );
        if( !ops[0].is_reg( REG_SP ) && ops[1].is_reg( REG_SP ) &&
            pfn && may_create_stkvars() && !is_defarg( F, ops[2].n ) )
        {
            // make a stack variable for Rd = add(sp, #I)
            if ( insn.create_stkvar( ops[2], ops[2].value, 0 /*unknown size*/ ) )
                op_stkvar( insn.ea, ops[2].n );
        }
        if( ops[0].is_reg( REG_SP ) && ops[1].is_reg( REG_SP ) &&
            pfn && may_trace_sp() )
        {
            // trace modification of SP register
            add_auto_stkpnt( pfn, insn.ea + insn.size, ops[2].value );
        }
        if( ops[1].is_reg( REG_PC ) &&
            !is_defarg( F, ops[2].n ) && !is_off( F, ops[2].n ) )
        {
            // create xref for Rd = add(pc, #I)
            op_offset( insn.ea, ops[2].n, REF_OFF32|REFINFO_NOBASE, ops[2].value );
        }
        break;
    }
}

static void handle_operand( const insn_t &insn, const op_t &op )
{
    fixup_data_t fd;
    flags_t F;

    switch( op.type )
    {
    case o_near:
        add_cref( insn.ea, op.addr, insn.itype == Hex_call? fl_CN : fl_JN );
        break;

    case o_mem:         // memXX(##u32)
    case o_mem_abs_set: // memXX(Re=##u32)
    case o_mem_abs_off: // memXX(Ru << #u2 + ##u32)
        insn.create_op_data( op.addr, op );
        insn.add_dref( op.addr, op.offb, dr_R );
        break;

    case o_displ: // memXX(Rs + #s11)
        set_immd( insn.ea );
        F = get_flags( insn.ea );
        if( op_adds_xrefs( F, op.n ) )
        {
            // create xref for offset expression
            ea_t target = insn.add_off_drefs( op, dr_R, OOF_ADDR | OOFS_IFSIGN | OOF_SIGNED | OOFW_32 );
            if( target != BADADDR )
                insn.create_op_data( target, op );
        }
        if( (op.reg == REG_SP || op.reg == REG_FP) && may_create_stkvars() &&
            !is_defarg( F, op.n ) && get_func( insn.ea ) != NULL )
        {
            // make a stack variable for memX({sp|fp} + #I)
            // NB: for vmem() the offset is in vector size units
            bool created = op.dtype == dt_byte64?
                insn.create_stkvar( op, op.addr * 128, 0 ) :
                insn.create_stkvar( op, op.addr, STKVAR_VALID_SIZE );
            if( created ) op_stkvar( insn.ea, op.n );
        }
        break;

    case o_imm:
        set_immd( insn.ea );
        F = get_flags( insn.ea );
        if( op_adds_xrefs( F, op.n ) )
        {
            insn.add_off_drefs( op, dr_O, OOFW_IMM | OOFW_32 |
                ((imm_op_flags( op ) & IMM_SIGNED)? OOF_SIGNED : 0) );
        }
        break;
    }
}

// emulate an instruction
ssize_t emu( const insn_t &insn )
{
    if( !is_basic_block_end( insn ) )
        add_cref( insn.ea, insn.ea + insn.size, fl_F );
    else if( get_auto_state() == AU_USED )
        recalc_spd( insn.ea );

    if( (insn.flags & INSN_DUPLEX) )
    {
        const op_t *ops = insn.ops;
        uint32_t itype = sub_insn_code( insn, 1 ), flags = insn_flags( insn, 1 );
        handle_insn( insn, itype, flags, ops );
        ops += get_num_ops( itype, flags );
        itype = sub_insn_code( insn, 0 ), flags = insn_flags( insn, 0 );
        handle_insn( insn, itype, flags, ops );
    }
    else
        handle_insn( insn, insn.itype, insn_flags( insn ), insn.ops );

    for( int i = 0; i < _countof(insn.ops); i++ )
        handle_operand( insn, insn.ops[i] );

    return 1; // ok
}

bool hex_is_call_insn( const insn_t &insn )
{
    return insn.itype == Hex_call ||
           insn.itype == Hex_callr;
}

static bool is_return( uint32_t itype, uint32_t /*flags*/, const op_t *ops, bool strict )
{
    // returns true if instruction is a return from sub-routine
    // TODO: should we check if it's conditional?
    if( !strict &&
        (itype == Hex_deallocframe_raw ||
         itype == Hex_deallocframe) )
        return true;
    if( itype == Hex_return_raw ||
        itype == Hex_return ||
        itype == Hex_jumpr && ops[0].is_reg( REG_LR ) )
        return true;
    return false;
}

bool hex_is_ret_insn( const insn_t &insn, bool strict )
{
    return visit_sub_insn( insn, is_return, strict );
}

ssize_t hex_is_align_insn( ea_t ea )
{
    const ea_t start = ea;
    insn_t insn;

    // just a zero word
    if( get_dword( ea ) == 0 )
        return 4;
    // a packet full of NOPs
    while( decode_insn( &insn, ea ) && insn.itype == Hex_nop )
    {
        // can't start in the middle of packet
        if( ea == start && !(insn.flags & INSN_PKT_BEG) ) break;
        ea += insn.size;
        if( (insn.flags & INSN_PKT_END) )
            return ea - start;
    }
    return 0;
}

bool hex_is_jump_func( func_t &pfn, ea_t *jump_target, ea_t *func_pointer )
{
    ea_t ea = pfn.start_ea;
    if( pfn.end_ea == ea + 16 &&                            // 16 bytes long:
        (get_dword( ea + 0 ) & 0x0000C000) == 0x00004000 && // extender
        (get_dword( ea + 4 ) & 0xffffe01f) == 0x6a49c00e && // r14 = add(pc, ##off@pcrel)
        get_dword( ea +  8 ) == 0x918ec01c &&               // r28 = memw(r14)
        get_dword( ea + 12 ) == 0x529cc000 )                // jumpr r28
    {
        uint32_t ext = get_dword( ea ), ins = get_dword( ea + 4 );
        uint32_t off = ((ext & 0x0fff0000) << 4) | ((ext & 0x3fff) << 6) | ((ins >> 7) & 0x3f);
        *jump_target = get_dword( ea + off );
        if( func_pointer ) *func_pointer = BADADDR;
        return true;
    }
    return false;
}

static bool create_frame( uint32_t itype, uint32_t /*flags*/, const op_t *ops, func_t *pfn )
{
    // allocframe(#I)
    if( itype == Hex_allocframe )
    {
        pfn->flags |= FUNC_FRAME; // uses frame pointer
        update_func( pfn );
        add_frame( pfn, ops[0].value/*local size*/, 8/*saved size*/, 0/*argsize*/ );
        return true;
    }
    // sp = add(sp, #I)
    if( itype == Hex_add && ops[0].is_reg( REG_SP ) &&
        ops[1].is_reg( REG_SP ) && ops[2].type == o_imm )
    {
        add_frame( pfn, -ops[2].value/*local size*/, 0/*saved size*/, 0/*argsize*/ );
        return true;
    }
    return false;
}

void hex_create_func_frame( func_t *pfn )
{
    ea_t ea = pfn->start_ea, end = pfn->end_ea;
    insn_t insn;

    for( int i = 0; i < 10 && ea < end; i++ )
    {
        if( !decode_insn( &insn, ea ) ||
            visit_sub_insn( insn, create_frame, pfn ) )
            return;

        ea += insn.size;
    }
}

int hex_is_sp_based( const insn_t &/*insn*/, const op_t &op )
{
    // Rd = add(sp, #I) or memX({sp|fp} + #I)
    if( op.type == o_displ && op.reg == REG_FP )
        return OP_FP_BASED | OP_SP_ADD;
    else
        return OP_SP_BASED | OP_SP_ADD;
}
