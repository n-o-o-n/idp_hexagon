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

static bool hex_is_basic_block_end( const insn_t &insn )
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
        // add SP change point
        // NB: compiler sometimes creates spurious allocframe(#0); deallocframe
        //     so we'll just ignore them
        if( ops[0].value == 0 && get_dword( insn.ea + insn.size ) == 0x901EC01E )
            break;
        if( pfn && may_trace_sp() )
            add_auto_stkpnt( pfn, packet_end( insn ), -(ops[0].value + 8) );
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
            // add SP change point for sp = add(sp, #I)
            add_auto_stkpnt( pfn, packet_end( insn ), ops[2].value );
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
            // unfortunately it produces wrong stack reference
            if( op.dtype == dt_byte64 )
                define_stkvar( get_func( insn.ea ), NULL, -(int)op.addr * 128, byte_flag(), NULL, 128 );
            else if( insn.create_stkvar( op, op.addr, STKVAR_VALID_SIZE ) )
                op_stkvar( insn.ea, op.n );
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
    if( !hex_is_basic_block_end( insn ) )
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

int hex_get_frame_retsize( const func_t &/*pfn*/ )
{
    // the return address is in LR, don't allocate stack for it
    return 0;
}

int hex_is_sp_based( const insn_t &/*insn*/, const op_t &op )
{
    // Rd = add(sp, #I) or memX({sp|fp} + #I)
    if( op.type == o_displ && op.reg == REG_FP )
        return OP_FP_BASED | OP_SP_ADD;
    else
        return OP_SP_BASED | OP_SP_ADD;
}

//
// type information support
//

void hex_get_cc_regs( cm_t /*cc*/, callregs_t &regs )
{
    // provide register allocation schema to IDA
    static const int r0_5[] = { REG_R0 + 0, REG_R0 + 1, REG_R0 + 2, REG_R0 + 3, REG_R0 + 4, REG_R0 + 5, -1 };
    regs.set( ARGREGS_GP_ONLY, r0_5, NULL );
}

bool hex_calc_retloc( cm_t /*cc*/, const tinfo_t &type, argloc_t &loc )
{
    if( !type.is_void() )
    {
        size_t size = type.get_size();
        if( size == BADSIZE ) return false;
        if( size <= 4 )
            loc.set_reg1( REG_R0 );
        else if( size <= 8 )
            loc.set_reg2( REG_R0, REG_R0 + 1 );
        else
        {
            // allocate on stack with pointer in R0
            scattered_aloc_t *sa = new scattered_aloc_t;
            argpart_t &regloc = sa->push_back();
            regloc.set_reg1( REG_R0 );
            regloc.off = 0;
            regloc.size = 4;
            argpart_t &stkloc = sa->push_back();
            stkloc.set_stkoff( 0 );
            stkloc.off = 0;
            stkloc.size = size;
            loc.consume_scattered( sa );
        }
    }
    return true;
}

bool hex_calc_arglocs( func_type_data_t &fti )
{
    // fill the return value location
    if( !hex_calc_retloc( fti.get_cc(), fti.rettype, fti.retloc ) )
        return false;

    uint32_t reg = 0, stk_sz = 0, align;
    // update stack size consumed by return value
    size_t size = fti.rettype.get_size();
    if( size > 8 ) stk_sz = size;

    // fill the arguments locations
    for( size_t i = 0; i < fti.size(); i++ )
    {
        funcarg_t &arg = fti[i];
        size = arg.type.get_size( &align );
        if( size == BADSIZE ) return false;
        if( size <= 4 && reg <= 5 )
        {
            arg.argloc.set_reg1( REG_R0 + reg );
            reg++;
        }
        else if( size <= 8 && reg < 5 )
        {
            // skip odd-numbered register
            reg = (reg + 1) & ~1;
            arg.argloc.set_reg2( REG_R0 + reg, REG_R0 + reg + 1 );
            reg += 2;
        }
        else
        {
            // use stack
            stk_sz = align_up( stk_sz, align );
            arg.argloc.set_stkoff( stk_sz );
            stk_sz += size;
        }
    }
    // update total size of stack arguments
    fti.stkargs = stk_sz;
    return true;
}

static bool insn_modifies_op0( uint32_t itype )
{
    // returns true if instruction writes to %0
    // NB: regenerate if instructions or their order changes!
    static uint32_t mod[] = {
        0xfffffffe, 0xbf7fffff, 0xffffffff, 0x000539c1, 0x022d0808, 0xf1c004c0, 0xffffffff, 0xffffffff,
        0xffffffff, 0xffffffff, 0xffffffff, 0xfffcffff, 0xff3fffff, 0x001fc1ff,
    };
    assert( itype < _countof(mod) * 32 );
    return (mod[ itype >> 5 ] >> (itype & 31)) & 1;
}

static bool _spoils( uint32_t itype, uint32_t flags, const op_t *ops, uint32_t reg1, uint32_t reg2 )
{
    if( !insn_modifies_op0( itype ) )
        return false;

    const op_t &op = ops[ get_op_index( flags ) + 0 ];
    return op.type == o_reg && (
           (reg_op_flags( op ) & REG_DOUBLE) && op.reg == reg1 && reg2 == reg1 + 1 ||
           op.reg == reg1 ||
           op.reg == reg2 );
}

// hack to skip our target function call
static ea_t s_call_ea = BADADDR;

static int spoils( const insn_t &insn, uint32_t reg1, uint32_t reg2 = ~0u )
{
    // checks if instruction modifies either reg1 or reg2
    // returns: 0 - doesn't; 1 - does; 2 - modifies all registers (i.e. function call)
    if( insn.ea != s_call_ea &&
        (insn.itype == Hex_call || insn.itype == Hex_callr) &&
       (insn_flags( insn ) & PRED_MASK) == 0 )
       return 2;

    return visit_sub_insn( insn, _spoils, reg1, reg2 )? 1 : 0;
}

static bool idaapi set_op_type( const insn_t &/*insn*/, const op_t &/*op*/, const tinfo_t &/*type*/, const char* /*name*/ )
{
    // called only for instructions that pass is_stkarg_write() test;
    // 'op' is insn.ops[src]; return value is ignored
    return false; // VERY simplified version :)
}

static bool _is_stkarg_write( uint32_t itype, uint32_t flags, const op_t *ops, int *src, int *dst )
{
    ops += get_op_index( flags );
    if( itype != Hex_mov || ops[0].type != o_displ ||
        ops[0].reg != REG_SP && ops[0].reg != REG_FP )
        return false;

    *src = ops[1].n;
    *dst = ops[0].n;
    return true;
}

static bool idaapi is_stkarg_write( const insn_t &insn, int *src, int *dst )
{
    // returns true if instruction writes to stack
    return visit_sub_insn( insn, _is_stkarg_write, src, dst );
}

void hex_use_arg_types( ea_t ea, func_type_data_t &fti, funcargvec_t &rargs )
{
    s_call_ea = ea;
    // set ea to the end of the packet
    ea = find_packet_end( ea ) + 4;
    gen_use_arg_tinfos(
        ea, &fti, &rargs,
        &set_op_type,
        &is_stkarg_write,
        NULL
    );
}

int hex_use_regarg_type( ea_t ea, const funcargvec_t &rargs )
{
    // allows IDA to put comments where the corresponding arguments are written in registers
    // NB: unfortunately this doesn't work when 2 or more registers are changed by a single instruction
    insn_t insn;

    if( !decode_insn( &insn, ea ) ) return -1;
    for( size_t i = 0; i < rargs.size(); i++ )
    {
        const argloc_t &loc = rargs[i].argloc;
        if( !loc.is_reg() ) continue;
        int status = spoils( insn, loc.reg1(), loc.is_reg1()? ~0u : loc.reg2() );
        // doesn't spoil?
        if( status == 0 ) continue;
        // spoils all regs?
        if( status == 2 ) return -2;
        return i;
    }
    return -1;
}
