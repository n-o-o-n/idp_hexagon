/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "common.h"

#define S_(color, str)                  SCOLOR_ON SCOLOR_##color str
#define S_INSN(str)                     S_(INSN, str)
#define S_KEYWORD(str)                  S_(KEYWORD, str)
#define S_SYMBOL(str)                   S_(SYMBOL, str)
#define S_NUMBER(str)                   S_(NUMBER, str)
#define S_REG(str)                      S_(REG, str)

// generate header
void out_header( outctx_t &ctx )
{
    ctx.gen_header( GH_PRINT_ALL );
}

// generate footer
void out_footer( outctx_t &ctx )
{
    qstring nbuf = get_colored_name( inf_get_start_ea() );
    const char *name = nbuf.c_str();
#if IDA_SDK_VERSION == 750
    asm_t &ash = ctx.ash;
#endif
    const char *end = ash.end;
    if ( end == NULL )
        ctx.gen_printf( -1, COLSTR("%s end %s",SCOLOR_AUTOCMT), ash.cmnt, name );
    else
        ctx.gen_printf( -1,
            COLSTR("%s",SCOLOR_ASMDIR) " " COLSTR("%s %s",SCOLOR_AUTOCMT),
            ash.end, ash.cmnt, name );
}

// user mode control registers
static const char *ctrl_rn[32] = {
    /*  0 */ "sa0",        "lc0",        "sa1",        "lc1",
    /*  4 */ "p3:0",       NULL,         "m0",         "m1",
    /*  8 */ "usr",        "pc",         "ugp",        "gp",
    /* 12 */ "cs0",        "cs1",        "upcyclelo",  "upcyclehi",
    /* 16 */ "framelimit", "framekey",   "pktcountlo", "pktcounthi",
    /* 20 */ NULL,         NULL,         NULL,         NULL,
    /* 24 */ NULL,         NULL,         NULL,         NULL,
    /* 28 */ NULL,         NULL,         "utimerlo",   "utimerhi",
};

// guest mode control registers (as in V67)
// TODO: change according to CPU version
static const char *guest_rn[32] = {
    /*  0 */ "gelr",       "gsr",        "gosp",       "gbadva",
    /*  4 */ "gcommit_1t", "gcommit_2t", "gcommit_3t", "gcommit_4t",
    /*  8 */ "gcommit_5t", "gcommit_6t", "gcycle_1t",  "gcycle_2t",
    /* 12 */ "gcycle_3t",  "gcycle_4t",  "gcycle_5t",  "gcycle_6t",
    /* 16 */ "gpmucnt4",   "gpmucnt5",   "gpmucnt6",   "gpmucnt7",
    /* 20 */ NULL,         NULL,         NULL,         NULL,
    /* 24 */ "gpcyclelo",  "gpcyclehi",  "gpmucnt0",   "gpmucnt1",
    /* 28 */ "gpmucnt2",   "gpmucnt3",   NULL,         NULL,
};

// monitor mode control registers (as in V67)
static const char *sys_rn[128] = {
    /*  0 */ "sgp0",       "sgp1",       "stid",       "elr",
    /*  4 */ "badva0",     "badva1",     "ssr",        "ccr",
    /*  8 */ "htid",       "badva",      "imask",      "gevb",
    /* 12 */ NULL,         NULL,         NULL,         NULL,
    /* 16 */ "evb",        "modectl",    "syscfg",     NULL,
    /* 20 */ "ipendad",    "vid",        "vid1",       "bestwait",
    /* 24 */ NULL,         "schedcfg",   NULL,         "cfgbase",
    /* 28 */ "diag",       "rev",        "pcyclelo",   "pcyclehi",
    /* 32 */ "isdbst",     "isdbcfg0",   "isdbcfg1",   "livelock",
    /* 36 */ "brkptpc0",   "brkptcfg0",  "brkptpc1",   "brkptcfg1",
    /* 40 */ "isdbmbxin",  "isdbmbxout", "isdben",     "isdbgpr",
    /* 44 */ "pmucnt4",    "pmucnt5",    "pmucnt6",    "pmucnt7",
    /* 48 */ "pmucnt0",    "pmucnt1",    "pmucnt2",    "pmucnt3",
    /* 52 */ "pmuevtcfg",  "pmustid0",   "pmuevtcfg1", "pmustid1",
    /* 56 */ "timerlo",    "timerhi",    "pmucfg",
};

static void hex_out_reg( outctx_t &ctx, uint32_t reg, uint32_t flags = 0 )
{
    // register prefix
    if( (flags & REG_PRE_NOT) ) ctx.out_symbol( '!' );
    else if( (flags & REG_PRE_NEG) ) ctx.out_symbol( '~' );

    ctx.out_tagon( COLOR_REG );
    if( (flags & REG_QUAD) )
    {
        // quad registers are valid only for HVX
        assert( IN_RANGE(reg, REG_V0, REG_V0 + 31) && ((reg - REG_V0) & 3) == 0 );
        ctx.out_printf( "v%u:%u", reg + 3 - REG_V0, reg - REG_V0 );
    }
    else if( (flags & REG_DOUBLE) )
    {
        // a pair of registers
        const char *name;
        switch( reg )
        {
        case REG_FP:      name = "lr:fp"; break;
        case REG_C0 + 0:  name = "lc0:sa0"; break;
        case REG_C0 + 2:  name = "lc1:sa1"; break;
        case REG_C0 + 6:  name = "m1:0"; break;
        case REG_C0 + 12: name = "cs1:0"; break;
        case REG_C0 + 14: name = "upcycle"; break;
        case REG_C0 + 18: name = "pktcount"; break;
        case REG_C0 + 30: name = "utimer"; break;
        case REG_G0 + 24: name = "gpcycle"; break;
        case REG_S0 + 0:  name = "sgp1:0"; break;
        case REG_S0 + 30: name = "pcycle"; break;
        case REG_S0 + 56: name = "timer"; break;
        default:          name = NULL; break;
        }
        if( name )
            ctx.out_line( name );
        else
        {
            if( IN_RANGE(reg, REG_R0, REG_R0 + 31) ) {
                assert( ((reg - REG_R0) & 1) == 0 );
                ctx.out_printf( "r%u:%u", reg + 1 - REG_R0, reg - REG_R0 );
            }
            else if( IN_RANGE(reg, REG_V0, REG_V0 + 31) ) {
                // may be either v1:0 (normal) or v0:1 (reversed)
                // NB: although we support reversed pair, it cannot currently be produced by compiler
                ctx.out_printf( "v%u:%u", (reg - REG_V0) ^ 1 , reg - REG_V0 );
            }
            else if( IN_RANGE(reg, REG_C0, REG_C0 + 31) ) {
                assert( ((reg - REG_C0) & 1) == 0 );
                ctx.out_printf( "c%u:%u", reg + 1 - REG_C0, reg - REG_C0 );
            }
            else if( IN_RANGE(reg, REG_G0, REG_G0 + 31) ) {
                assert( ((reg - REG_G0) & 1) == 0 );
                ctx.out_printf( "g%u:%u", reg + 1 - REG_G0, reg - REG_G0 );
            }
            else if( IN_RANGE(reg, REG_S0, REG_S0 + 127) ) {
                assert( ((reg - REG_S0) & 1) == 0 );
                ctx.out_printf( "s%u:%u", reg + 1 - REG_S0, reg - REG_S0 );
            }
            else
                goto unknown;
        }
    }
    else
    {
        // a single register
        if( reg < REG_SP ) {
            ctx.out_printf( "r%u", reg - REG_R0 );
        }
        else if( reg < REG_P0 ) {
            static const char *rn[] = { "sp", "fp", "lr" };
            ctx.out_line( rn[ reg - REG_SP ] );
        }
        else if( reg < REG_V0 ) {
            ctx.out_printf( "p%u", reg - REG_P0 );
        }
        else if( reg < REG_Q0 ) {
            ctx.out_printf( "v%u", reg - REG_V0 );
        }
        else if( reg < REG_Z ) {
            ctx.out_printf( "q%u", reg - REG_Q0 );
        }
        else if( reg < REG_C0 ) {
            static const char *rn[] = { "z", "vtmp" };
            ctx.out_line( rn[ reg - REG_Z ] );
        }
        else if( reg < REG_G0 ) {
            const char *name = ctrl_rn[ reg - REG_C0 ];
            if( name ) ctx.out_line( name );
            else       ctx.out_printf( "c%u", reg - REG_C0 );
        }
        else if( reg < REG_S0 ) {
            const char *name = guest_rn[ reg - REG_G0 ];
            if( name ) ctx.out_line( name );
            else       ctx.out_printf( "g%u", reg - REG_G0 );
        }
        else if( reg < REG_NUM ) {
            const char *name = sys_rn[ reg - REG_S0 ];
            if( name ) ctx.out_line( name );
            else       ctx.out_printf( "s%u", reg - REG_S0 );
        }
        else {
        unknown:
            ctx.out_line( "<unknown>" );
        }
    }
    ctx.out_tagoff( COLOR_REG );

    // register postfix
    if( (flags >> REG_POST_SHIFT) )
    {
        const char *postfix[16] = {
            NULL, ".new", ".cur", ".tmp", ".l", ".h", "*", ".b", ".h", ".w",
            ".ub", ".uh", ".uw", ".n", ".c",
        };
        ctx.out_keyword( postfix[(flags >> REG_POST_SHIFT) & 0xF] );
        if( (flags & REG_POST_INC) )
            ctx.out_line( S_SYMBOL("++") );
    }
}

static void hex_out_mem( outctx_t &ctx, uint32_t type )
{
    static const char *types[] = {
        "memb", "membh", "memub", "memubh", "memh", "memuh",
        "memw", "memd",  "vmem",  "vmem",  "vmemu",
    };
    ctx.out_line( types[ type & MEM_TYPE_MASK ], COLOR_INSN );
    if( (type & MEM_FIFO) )
        ctx.out_line( "_fifo", COLOR_INSN );
    if( (type & MEM_LOCKED) )
        ctx.out_line( "_locked", COLOR_INSN );
}

ssize_t out_operand( outctx_t &ctx, const op_t &op )
{
    uint32_t flags;
    ea_t ea;

    // memory accesses
    if( op.type == o_mem || op.type == o_displ ||
        o_mem_abs_set <= op.type && op.type <= o_mem_locked )
    {
        hex_out_mem( ctx, mem_op_type( op ) );
        ctx.out_symbol( '(' );
        switch( op.type )
        {
        case o_mem:          // memXX(##u32)
            ctx.out_line( "##", COLOR_SYMBOL );
            ctx.out_value( op, OOFW_IMM | OOFW_32 );
            break;
        case o_mem_abs_set:  // memXX(Re=##u32)
            hex_out_reg( ctx, op.reg );
            ctx.out_line( " = ##", COLOR_SYMBOL );
            ctx.out_value( op, OOFW_IMM | OOFW_32 );
            break;
        case o_mem_abs_off:  // memXX(Ru << #u2 + ##u32)
            hex_out_reg( ctx, op.reg );
            ctx.out_line( S_SYMBOL("<<#") S_NUMBER("") );
            ctx.out_btoa( op.specflag2, 10 );
            ctx.out_line( S_SYMBOL(" + ##") );
            ctx.out_value( op, OOFW_IMM | OOFW_32 );
            break;
        case o_displ:        // memXX(Rs + #s11) or memXX(gp + #u16)
            hex_out_reg( ctx, op.reg );
            if( op.addr != 0 || op.reg == REG_SP || op.reg == REG_GP ) {
                ctx.out_line( " + #", COLOR_SYMBOL );
                if( (op.specflag2 & IMM_EXTENDED) ) ctx.out_symbol( '#' );
                ctx.out_value( op, OOF_ADDR | OOFS_IFSIGN | OOF_SIGNED | OOFW_32 );
            }
            break;
        case o_mem_ind_off:  // memXX(Rs + Ru << #u2)
            hex_out_reg( ctx, op.reg >> 8 );
            ctx.out_line( " + ", COLOR_SYMBOL );
            hex_out_reg( ctx, op.reg & 0xFF );
            ctx.out_line( "<<#", COLOR_SYMBOL );
            ctx.out_value( op, OOFW_IMM | OOFW_32 );
            break;
        case o_mem_inc_imm:  // memXX(Rx++#s4)
            hex_out_reg( ctx, op.reg );
            ctx.out_line( "++ #", COLOR_SYMBOL );
            ctx.out_value( op, OOFW_IMM | OOFS_IFSIGN | OOF_SIGNED | OOFW_32 );
            break;
        case o_mem_inc_reg:  // memXX(Rx++Mu)
            hex_out_reg( ctx, op.reg );
            ctx.out_line( "++ ", COLOR_SYMBOL );
            hex_out_reg( ctx, op.specflag2 );
            break;
        case o_mem_circ_imm: // memXX(Rx++#s4:circ(Mu))
            hex_out_reg( ctx, op.reg );
            ctx.out_line( "++ #", COLOR_SYMBOL );
            ctx.out_value( op, OOFW_IMM | OOFS_IFSIGN | OOF_SIGNED | OOFW_32 );
            ctx.out_line( S_KEYWORD(":circ") S_SYMBOL("(") );
            hex_out_reg( ctx, op.specflag2 );
            ctx.out_symbol( ')' );
            break;
        case o_mem_circ_reg: // memXX(Rx++I:circ(Mu))
            hex_out_reg( ctx, op.reg );
            ctx.out_line( S_SYMBOL("++ ") S_REG("I") S_KEYWORD(":circ") S_SYMBOL("(") );
            hex_out_reg( ctx, op.specflag2 );
            ctx.out_symbol( ')' );
            break;
        case o_mem_inc_brev: // memXX(Rx++Mu:brev)
            hex_out_reg( ctx, op.reg );
            ctx.out_line( "++ ", COLOR_SYMBOL );
            hex_out_reg( ctx, op.specflag2 );
            ctx.out_keyword( ":brev" );
            break;
        case o_mem_locked:   // memXX_locked(Rs[,Pd])
            hex_out_reg( ctx, op.reg );
            if( op.specflag2 ) {
                ctx.out_symbol( ',' );
                hex_out_reg( ctx, op.specflag2 );
            }
            break;
        }
        ctx.out_symbol( ')' );
        if( mem_op_type( op ) == MEM_VNT ) ctx.out_keyword( ":nt" );
        return 1;
    }

    // all other types
    switch( op.type )
    {
    case o_reg:
        hex_out_reg( ctx, op.reg, op.specval );
        break;
    case o_imm:
        flags = imm_op_flags( op );
        if( (flags & IMM_EXTENDED) ) ctx.out_symbol( '#' );
        ctx.out_symbol( '#' );
        ctx.out_value( op, OOFW_IMM | OOFW_32 | ((flags & IMM_SIGNED)? OOF_SIGNED : 0) );
        if( (flags & IMM_PCREL) ) ctx.out_keyword( "@pcrel" );
        break;
    case o_reg_off:
        hex_out_reg( ctx, op.reg );
        if( op.value != 0 ) {
            ctx.out_line( " + #", COLOR_SYMBOL );
            ctx.out_value( op, OOFW_IMM | OOFW_32 );
        }
        break;
    case o_near:
        ea = to_ea( ctx.insn.cs, op.addr );
        if ( !ctx.out_name_expr( op, ea, op.addr ) )
        {
            ctx.out_value( op, OOF_ADDR | OOF_NUMBER | OOFS_NOSIGN | OOFW_32 );
            remember_problem( PR_NONAME, ctx.insn.ea );
        }
        break;
    default:
        return -1;
    }
    return 1;
}

static void hex_out_op_line( outctx_t &ctx, const char *str, uint32_t op_idx )
{
    // outputs pre-colored line with operands
    while( char c = *str++ )
    {
        // %№ means operand number №
        if( c == '%' ) ctx.out_one_operand( op_idx + *str++ - '0' );
        else           ctx.out_char( c );
    }
}

static uint32_t hex_out_predicate( outctx_t &ctx, uint32_t ptype, uint32_t op_idx )
{
    ctx.out_line( S_INSN("if")S_SYMBOL(" (") );
    if( ptype >= PRED_NE ) {
        ctx.out_char( '!' );
        ptype -= PRED_NOT;
    }
    static const char *pred[] = {
    /* REG */ "%0",
    /* EQ  */ S_INSN("cmp")S_KEYWORD(".eq")S_SYMBOL("(") "%0" S_SYMBOL(", ") "%1" S_SYMBOL(")"),
    /* GT  */ S_INSN("cmp")S_KEYWORD(".gt")S_SYMBOL("(") "%0" S_SYMBOL(", ") "%1" S_SYMBOL(")"),
    /* GTU */ S_INSN("cmp")S_KEYWORD(".gtu")S_SYMBOL("(") "%0" S_SYMBOL(", ") "%1" S_SYMBOL(")"),
    /* BS0 */ S_INSN("tstbit")S_SYMBOL("(") "%0" S_SYMBOL(", ") "%1" S_SYMBOL(")"),
    /* NE0 */ "%0" S_SYMBOL(" != ") "%1",
    /* GE0 */ "%0" S_SYMBOL(" >= ") "%1",
    /* EQ0 */ "%0" S_SYMBOL(" == ") "%1",
    /* LE0 */ "%0" S_SYMBOL(" <= ") "%1",
    };
    hex_out_op_line( ctx, pred[ptype - 1], op_idx );
    ctx.out_line( S_SYMBOL(") ") );
    return op_idx + (ptype == PRED_REG? 1 : 2);
}

static uint32_t hex_out_insn( outctx_t &ctx, uint32_t itype, uint32_t flags, uint32_t op_idx )
{
    // output predicate
    if( (flags & PRED_MASK) != PRED_NONE )
        op_idx = hex_out_predicate( ctx, flags & PRED_MASK, op_idx );

    // output instruction body
    const char *tmpl = get_insn_template( itype );
    uint32_t maxop = 0, color = 0;
    while( char c = *tmpl++ )
    {
        if( c == '%' ) {
            c = *tmpl++;
            if( '0' <= c && c <= '9' ) {
                ctx.out_one_operand( op_idx + c - '0' );
                if( c > maxop ) maxop = c;
            }
            else if( c == 's' && (flags & SZ_MASK) != SZ_NONE ) {
                static const char *sz[8] = { "", "b", "h", "w", "d", "ub", "uh", "uw" };
                ctx.out_line( sz[(flags & SZ_MASK) >> SZ_SHIFT], COLOR_INSN );
            }
            else if( c == 'c' ) {
                static const char *cmp[] = { ".eq", ".gt", ".gtu", ".ge", ".uo" };
                ctx.out_keyword( cmp[(flags & CMP_MASK) >> CMP_SHIFT] );
            }
            else if( c == 't' && (flags & JMP_MASK) != JMP_NONE ) {
                static const char *hint[] = { "", ":t", ":nt" };
                ctx.out_keyword( hint[(flags & JMP_MASK) >> JMP_SHIFT] );
            }
            else if( c == 'g' ) {
                static const char *sg[] = { ".w", ".h" };
                ctx.out_keyword( sg[(flags & SG_MASK) >> SG_SHIFT] );
            }
            color = 0;
        }
        else if( c == '=' ) {
            static const char *ass[] = { " = ", " = !", " += ", " -= ", " &= ", " |= ", " ^= " };
            ctx.out_line( ass[(flags & IAT_MASK) >> IAT_SHIFT], COLOR_SYMBOL );
            color = 0;
        }
        else if( c == ';' ) {
            if( (idpflags & HEX_CR_FOR_DUPLEX) )
            {
                ctx.flush_outbuf();
                ctx.out_line( "  ", COLOR_SYMBOL );
            } else
                ctx.out_line( "; ", COLOR_SYMBOL );
            color = 0;
        } else {
            // change color if necessary
            uint32_t new_color = isalnum(c)? COLOR_INSN : COLOR_SYMBOL;
            if( color != new_color )
                ctx.out_tagon( color = new_color );
            ctx.out_char( c );
        }
    }
    // output postfix
    if( (flags & IPO_MASK) != IPO_NONE ) {
        static const char *post[] = {
            NULL, ":<<1", ":<<1:rnd", ":<<1:rnd:sat", ":<<1:rnd:sat:shift", ":<<1:sat", ":<<1:sat:shift",
            ":<<16", ":carry", ":carry:sat", ":crnd", ":crnd:sat", ":rnd", ":rnd:>>1:sat", ":rnd:sat",
            ":sat", ":sat:<<16", ":chop", ":lib", ":neg", ":pos", ":scale", ":nomatch"
        };
        ctx.out_keyword( post[(flags & IPO_MASK) >> IPO_SHIFT] );
    }
    // returns next operand index
    return op_idx + maxop - '0' + 1;
}

static bool is_single( const insn_t insn )
{
    // packet starts and ends here?
    // note: end of loop requires braces
    if( (insn.flags & (INSN_PKT_BEG | INSN_PKT_END | INSN_DUPLEX | INSN_ENDLOOP01)) != (INSN_PKT_BEG | INSN_PKT_END) )
        return false;
    // complex instruction?
    if( Hex_cmp_jump <= insn.itype && insn.itype <= Hex_tstbit_jump )
        return false;
    return true;
}
static void out_pkt_beg( outctx_t &ctx )
{
    if( !(idpflags & HEX_BRACES_FOR_SINGLE) && is_single( ctx.insn ) )
        ctx.out_line( "  ", COLOR_SYMBOL );
    else if( (idpflags & HEX_OBRACE_ALONE) )
    {
        ctx.out_symbol( '{' );
        ctx.flush_outbuf();
        ctx.out_line( "  ", COLOR_SYMBOL );
    } else
        ctx.out_line( "{ ", COLOR_SYMBOL );
}

static void out_pkt_end( outctx_t &ctx )
{
    if( !(idpflags & HEX_BRACES_FOR_SINGLE) && is_single( ctx.insn ) )
        return;
    if( (idpflags & HEX_CBRACE_ALONE) )
    {
        ctx.flush_outbuf();
        ctx.out_symbol( '}' );
    }
    else
        ctx.out_line( " }", COLOR_SYMBOL );
    if( (ctx.insn.flags & INSN_ENDLOOP01) == INSN_ENDLOOP01 )
        ctx.out_keyword( " :endloop01" );
    else
    {
        if( (ctx.insn.flags & INSN_ENDLOOP0) )
            ctx.out_keyword( " :endloop0" );
        if( (ctx.insn.flags & INSN_ENDLOOP1) )
            ctx.out_keyword( " :endloop1" );
    }
}

// output an instruction and its operands
void out_insn( outctx_t &ctx )
{
    if( (ctx.insn.flags & INSN_PKT_BEG) )
        out_pkt_beg( ctx );
    else
        ctx.out_line( "  ", COLOR_SYMBOL );
    if( (ctx.insn.flags & INSN_DUPLEX) )
    {
        uint32_t flags = insn_flags( ctx.insn, 1 );
        uint32_t op_idx = hex_out_insn( ctx, sub_insn_code( ctx.insn, 1 ), flags, 0 );
        if( (idpflags & HEX_CR_FOR_DUPLEX) )
        {
            ctx.flush_outbuf();
            ctx.out_line( "  ", COLOR_SYMBOL );
        } else
            ctx.out_line( "; ", COLOR_SYMBOL );
        flags = insn_flags( ctx.insn, 0 );
        hex_out_insn( ctx, sub_insn_code( ctx.insn, 0 ), flags, op_idx );
    }
    else
    {
        uint32_t flags = insn_flags( ctx.insn );
        hex_out_insn( ctx, ctx.insn.itype, flags, 0 );
    }
    if( (ctx.insn.flags & INSN_PKT_END) )
        out_pkt_end( ctx );
    ctx.flush_outbuf();
}
