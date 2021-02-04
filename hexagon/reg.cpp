/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "common.h"

// configuration flags
uint16_t idpflags = HEX_BRACES_FOR_SINGLE | HEX_CR_FOR_DUPLEX;

static const char* set_idp_options( const char *keyword, int value_type, const void *value )
{
    if( !keyword )
    {
        static const char form[] =
R"(HELP
Open brace is left alone
------------------------
If this option is on, the open brace of a packet will be
placed on its own in a line before packet body:

    {
      r2 = memh(r4 + #8)
      memw(r5) = r2.new }


Closing brace is left alone
---------------------------
If this option is on, the closing brace of a packet will be
placed on its own in a line after packet body:

    { r2 = memh(r4 + #8)
      memw(r5) = r2.new
    }


Use braces for single instructions
----------------------------------
If this option is off, packets with a single instruction
will not use packet braces.


Insert CR inside duplex instructions
------------------------------------
If this option is off, the sub-instructions inside duplex
or complex instructions will be separated by semicolon:

    r1 = #0xF; r0 = add(sp, #0x28)

If this option is on, the sub-instructions inside duplex
or complex instructions will be separated by new line:

    r1 = #0xF
    r0 = add(sp, #0x28)

ENDHELP
Hexagon specific options

<~O~pen brace is left alone:C>
<~C~losing brace is left alone:C>
<~U~se braces for single instructions:C>
<~I~nsert CR inside duplex instructions:C>>
)";
        ask_form( form, &idpflags );
        return IDPOPT_OK;
    }
    else
    {
        if( value_type != IDPOPT_BIT )
            return IDPOPT_BADTYPE;
        if( !strcmp( keyword, "HEX_OBRACE_ALONE" ) )
        {
            setflag( idpflags, HEX_OBRACE_ALONE, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        else if( !strcmp( keyword, "HEX_CBRACE_ALONE" ) )
        {
            setflag( idpflags, HEX_CBRACE_ALONE, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        else if( !strcmp( keyword, "HEX_BRACES_FOR_SINGLE" ) )
        {
            setflag( idpflags, HEX_BRACES_FOR_SINGLE, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        else if( !strcmp( keyword, "HEX_CR_FOR_DUPLEX" ) )
        {
            setflag( idpflags, HEX_CR_FOR_DUPLEX, *(int*)value != 0 );
            return IDPOPT_OK;
        }
        return IDPOPT_BADKEY;
    }
}

static ssize_t idaapi notify( void*, int notification_code, va_list va )
{
    switch( notification_code )
    {
    case processor_t::ev_set_idp_options: {
        auto keyword = va_arg( va, const char* );
        auto value_type = va_arg( va, int );
        auto value = va_arg( va, const void* );
        auto errbuf = va_arg( va, const char** );

        const char *err = set_idp_options( keyword, value_type, value );
        if( err == IDPOPT_OK ) return 1;
        if( errbuf ) *errbuf = err;
        return -1;
    }
    case processor_t::ev_loader_elf_machine: {
        // note: this callback is called only if the user clicked "Set" button
        // in "Load a new file" dialog
        auto li = va_arg( va, linput_t* );
        auto machine_type = va_arg( va, int );
        auto p_procname = va_arg( va, const char** );
        auto p_pd = va_arg( va, proc_def_t** );
        return loader_elf_machine( li, machine_type, p_procname, p_pd );
    }
    case processor_t::ev_ana_insn: {
        return ana( *va_arg( va, insn_t* ) );
    }
    case processor_t::ev_emu_insn: {
        return emu( *va_arg( va, const insn_t* ) );
    }
    case processor_t::ev_out_header: {
        out_header( *va_arg( va, outctx_t* ) );
        break;
    }
    case processor_t::ev_out_footer: {
        out_footer( *va_arg( va, outctx_t* ) );
        break;
    }
    case processor_t::ev_out_insn: {
        out_insn( *va_arg( va, outctx_t* ) );
        break;
    }
    case processor_t::ev_out_operand: {
        auto ctx = va_arg( va, outctx_t* );
        auto op = va_arg( va, const op_t* );
        return out_operand( *ctx, *op );
    }
    case processor_t::ev_is_call_insn: {
        return hex_is_call_insn( *va_arg( va, const insn_t* ) )? 1 : -1;
    }
    case processor_t::ev_is_ret_insn: {
        // not strictly necessary, everything works as is
        auto insn = va_arg( va, const insn_t* );
        auto strict = va_argi( va, bool );
        return hex_is_ret_insn( *insn, strict )? 1 : -1;
    }
    case processor_t::ev_may_be_func: {
        auto insn = va_arg( va, const insn_t* );
        auto state = va_arg( va, int );
        return hex_may_be_func( *insn, state );
    }
    case processor_t::ev_is_align_insn: {
        return hex_is_align_insn( va_arg( va, ea_t ) );
    }
    case processor_t::ev_is_jump_func: {
        auto pfn = va_arg( va, func_t* );
        auto jump_target = va_arg( va, ea_t* );
        auto func_pointer = va_arg( va, ea_t* );
        return hex_is_jump_func( *pfn, jump_target, func_pointer )? 1 : 0;
    }
    case processor_t::ev_create_func_frame: {
        hex_create_func_frame( va_arg( va, func_t* ) );
        return 1;
    }
    case processor_t::ev_get_frame_retsize: {
        auto frsize = va_arg( va, int* );
        auto pfn = va_arg( va, const func_t* );
        *frsize = hex_get_frame_retsize( *pfn );
        return 1;
    }
    case processor_t::ev_is_sp_based: {
        auto mode = va_arg( va, int* );
        auto insn = va_arg( va, const insn_t* );
        auto op = va_arg( va, const op_t* );
        *mode = hex_is_sp_based( *insn, *op );
        return 1;
    }
    case processor_t::ev_realcvt: {
        // must be implemented for floats to work
        auto m = va_arg( va, void* );
        auto e = va_arg( va, uint16* );
        auto swt = va_argi( va, uint16 );
        int code = ieee_realcvt( m, e, swt );
        return code == 0? 1 : code;
    }
    //
    // type information callbacks
    //
    case processor_t::ev_decorate_name: {
        auto outbuf = va_arg( va, qstring* );
        auto name = va_arg( va, const char* );
        auto mangle = va_argi( va, bool );
        auto cc = va_argi( va, cm_t );
        auto type = va_arg( va, tinfo_t* );
        return gen_decorate_name( outbuf, name, mangle, cc, type );
    }
    case processor_t::ev_get_cc_regs: {
        auto regs = va_arg( va, callregs_t* );
        auto cc = va_arg( va, cm_t );
        hex_get_cc_regs( cc, *regs );
        return 1;
    }
    case processor_t::ev_get_stkarg_offset: {
        // offset from SP to the first stack argument
        return 0;
    }
    case processor_t::ev_calc_arglocs: {
        auto fti = va_arg( va, func_type_data_t* );
        return hex_calc_arglocs( *fti )? 1 : -1;
    }
    case processor_t::ev_calc_retloc: {
        auto retloc = va_arg( va, argloc_t* );
        auto rettype = va_arg( va, const tinfo_t* );
        auto cc = va_arg( va, cm_t );
        return hex_calc_retloc( cc, *rettype, *retloc )? 1 : -1;
    }
    case processor_t::ev_use_arg_types: {
        auto ea = va_arg( va, ea_t );
        auto fti = va_arg( va, func_type_data_t* );
        auto rargs = va_arg( va, funcargvec_t* );
        hex_use_arg_types( ea, *fti, *rargs );
        return 1;
    }
    case processor_t::ev_use_regarg_type: {
        auto idx = va_arg( va, int* );
        auto ea = va_arg( va, ea_t );
        auto rargs = va_arg( va, const funcargvec_t* );
        *idx = hex_use_regarg_type( ea, *rargs );
        return 1;
    }
    case processor_t::ev_max_ptr_size:
        return inf_get_cc_size_l();
    case processor_t::ev_get_default_enum_size:
        return inf_get_cc_size_e();
    }
    // by default always return 0
    return 0;
}

// GNU Assembler description
static const asm_t elf_asm = {
    ASH_HEXF3 |                 // hex 0x123 format
    ASD_DECF0 |                 // dec 123 format
    ASO_OCTF1 |                 // oct 012345 format
    ASB_BINF3 |                 // bin 0b110 format
    AS_N2CHR |                  // can't have 2 byte char consts
    AS_LALIGN |                 // labels at "align" keyword are supported
    AS_COLON,                   // create colons after data names
    0,                          // uflag
    "ELF Assembler",            // name
    0,                          // help
    NULL,                       // header
    ".org",                     // org directive
    ".end",                     // end directive
    "//",                       // comment string
    '"',                        // string delimiter
    '\'',                       // char delimiter (in fact it's a single left quote symbol)
    "\"'",                      // special symbols in char and string constants
    ".ascii",                   // ascii string directive
    ".byte",                    // byte directive
    ".short",                   // word directive, aka .half,.hword,.2byte
    ".long",                    // dword  (4 bytes), aka .word,.int,.4byte
    ".quad",                    // qword  (8 bytes)
    NULL,                       // oword  (16 bytes)
    ".float",                   // float  (4 bytes)
    ".double",                  // double (8 bytes)
    NULL,                       // long double (10/12 bytes)
    NULL,                       // packed decimal real
    "#d dup(#v)",               // dups (actually we need to use ".fill #d, #s(1,2,4,8,16), #v"
                                //       but IDA uses it exactly as dup in MASM)
    ".space %s",                // uninited arrays
    ".equ",                     // 'equ'
    NULL,                       // 'seg' prefix
    ".",                        // current instruction pointer
    NULL,                       // function header
    NULL,                       // function footer
    ".global",                  // public
    NULL,                       // weak
    NULL,                       // extrn
    ".common",                  // comdef
    NULL,                       // get name of type
    ".align",                   // align
    '(', ')',                   // lbrace, rbrace
    "%",                        // mod
    "&",                        // and
    "|",                        // or
    "^",                        // xor
    "~",                        // not
    ">>",                       // shl
    "<<",                       // shr
    NULL,                       // size of type (format string)
    0,                          // flag2
    NULL,                       // cmnt2
    NULL,                       // low8 operation
    NULL,                       // high8 operation
    "LO(%s)",                   // low16 operation
    "HI(%s)",                   // high16 operation
    NULL,                       // the include directive (format string)
    NULL,                       // vstruc
    NULL,                       // 'rva' keyword for image based offsets
    NULL,                       // 32-byte (256-bit) data
};

// supported assemblers
static const asm_t *const asms[] = { &elf_asm, NULL };

// short and long names for our module
static const char *const shnames[] = {
    "QDSP6",
    NULL
};
static const char *const lnames[] = {
    "Qualcomm Hexagon DSP",
    NULL
};

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------
processor_t LPH = {
    IDP_INTERFACE_VERSION,  // version
    0x8666,                 // id
                            // flag:
    PR_CNDINSNS |           // has conditional instructions
    PR_NO_SEGMOVE |         // the processor module doesn't support move_segm() (i.e. the user can't move segments)
    PR_USE32 |              // supports 32-bit addressing?
    PR_DEFSEG32 |           // segments are 32-bit by default
    PRN_HEX |               // default number representation: == hex
    PR_TYPEINFO |           // support the type system notifications
    PR_USE_ARG_TYPES |      // use processor_t::ev_use_arg_types callback
    PR_ALIGN,               // all data items should be aligned properly
                            // flag2:
    PR2_REALCVT |           // the module has 'realcvt' event implementation
    PR2_IDP_OPTS,           // the module has processor-specific configuration options
    8,                      // cnbits: 8 bits in a byte for code segments
    8,                      // dnbits: 8 bits in a byte for other segments
    shnames,                // array of short processor names
                            // the short names are used to specify the processor
                            // with the -p command line switch)
    lnames,                 // array of long processor names
                            // the long names are used to build the processor type
                            // selection menu
    asms,                   // array of target assemblers
    notify,                 // the kernel event notification callback
    NULL,                   // regsiter names
    0,                      // number of registers

    -1,                     // index of first segment register
    -1,                     // index of last segment register
    0,                      // size of a segment register in bytes
    0, 0,                   // index of CS & DS registers

    NULL,                   // no known code start sequences
    NULL,                   // no known 'return' instructions

    0,                      // icode of 1st instruction
    0,                      // icode of last instruction + 1
    NULL,                   // array of instructions

    0,                      // sizeof(long double) -- doesn't exist
    { 0, 7, 15, 0 },        // number of symbols after decimal point (must define for floats to work)
                            // 16-bit float (0-does not exist)
                            // normal float
                            // normal double
                            // long double (0-does not exist)
    0,                      // Icode of return instruction (it's ok to give any of possible return instructions)
};
