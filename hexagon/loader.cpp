/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "common.h"
#include "../../ldr/elf/elfbase.h"
#include "../../ldr/elf/elf.h"
#include "elfr_hexagon.h"

//
// for more information, see [80-N2040-23] "Qualcomm Hexagon ABI", section 12.4
//

enum {
    // fixed relocation masks
    LO_MASK         = 0x00c03fff,
    B7_MASK         = 0x00001f18,
    B9_MASK         = 0x003000fe,
    B13_MASK        = 0x00202ffe,
    B15_MASK        = 0x00df20fe,
    B22_MASK        = 0x01ff3ffe,
    M21_MASK        = 0x0fff3fe0,
    M25_MASK        = 0x0fff3fef,
    R6_MASK         = 0x000007e0,
    X26_MASK        = 0x0fff3fff,
};

// base address of small data area, used for GP-relative relocations
uint32_t _SDA_BASE_ = 0;
// base address for thread-local relocations
uint32_t _TLS_START_ = 0;
// address of global offset table
uint32_t _GOT_ = 0;
// address of procedure linkage table
uint32_t _PLT_ = 0;
// base address for message base optimization
uint32_t _MSG_BASE_ = 0;

// process e_flags field of ELF header
static const char* proc_flag( reader_t&, uint32 &e_flags )
{
    const char *opts = NULL;
    switch( e_flags ) {
    case EF_HEXAGON_MACH_V4:   opts = "Hexagon V4"; break;
    case EF_HEXAGON_MACH_V5:   opts = "Hexagon V5"; break;
    case EF_HEXAGON_MACH_V55:  opts = "Hexagon V55"; break;
    case EF_HEXAGON_MACH_V60:  opts = "Hexagon V60"; break;
    case EF_HEXAGON_MACH_V61:  opts = "Hexagon V61"; break;
    case EF_HEXAGON_MACH_V62:  opts = "Hexagon V62"; break;
    case EF_HEXAGON_MACH_V65:  opts = "Hexagon V65"; break;
    case EF_HEXAGON_MACH_V66:  opts = "Hexagon V66"; break;
    case EF_HEXAGON_MACH_V67:  opts = "Hexagon V67"; break;
    case EF_HEXAGON_MACH_V67T: opts = "Hexagon V67 Small Core"; break;
    }
    // clear used flags to prevent infinite loop
    if( opts ) e_flags = 0;
    // TODO: use flags to limit instructions support
    return opts;
}

static uint32_t get_mask_R6( uint32_t word )
{
    static const struct { uint32_t cmp, imm; } r6[] = {
        {0x38000000, 0x0000201f}, {0x39000000, 0x0000201f},
        {0x3e000000, 0x00001f80}, {0x3f000000, 0x00001f80},
        {0x40000000, 0x000020f8}, {0x41000000, 0x000007e0},
        {0x42000000, 0x000020f8}, {0x43000000, 0x000007e0},
        {0x44000000, 0x000020f8}, {0x45000000, 0x000007e0},
        {0x46000000, 0x000020f8}, {0x47000000, 0x000007e0},
        {0x6a000000, 0x00001f80}, {0x7c000000, 0x001f2000},
        {0x9a000000, 0x00000f60}, {0x9b000000, 0x00000f60},
        {0x9c000000, 0x00000f60}, {0x9d000000, 0x00000f60},
        {0x9f000000, 0x001f0100}, {0xab000000, 0x0000003f},
        {0xad000000, 0x0000003f}, {0xaf000000, 0x00030078},
        {0xd7000000, 0x006020e0}, {0xd8000000, 0x006020e0},
        {0xdb000000, 0x006020e0}, {0xdf000000, 0x006020e0}
    };

    // is it a duplex?
    if( (word & 0x0000c000) == 0 ) return 0x03f00000; // Rd = #Ii (6 bits)
    for( auto i : r6 )
    {
        if( (word & 0xff000000) == i.cmp )
            return i.imm;
    }
    warning( "unrecognized instruction for R_HEX_6 relocation: 0x%08X\n", word );
    return 0;
}

static uint32_t get_mask_R8( uint32_t word )
{
    if( (word & 0x1800c000) == 0x00000000 ) return 0x07f00000; // duplex Rx16 = add(Rx16in,#Ii) (7 bits)
    if( (word & 0x1C00c000) == 0x08000000 ) return 0x03f00000; // duplex Rd16 = #Ii (6 bits)
    if( (word & 0xff000000) == 0xde000000 ) return 0x00e020e8; // Rx = <op1>(#Ii,<shift>(Rx,#II))
    if( (word & 0xff000000) == 0x3c000000 ) return 0x0000207f; // memX(Rs+#Ii) = #II
    return 0x00001fe0; // combine/mux
}

static uint32_t get_mask_R11( uint32_t word )
{
    if( (word & 0xff000000) == 0xa1000000 ) return 0x060020ff; // memX(Rs+#Ii) = Rt
    return 0x06003fe0;
}

static uint32_t get_mask_R16( uint32_t word )
{
    // is it a duplex?
    if( (word & 0x0000c000) == 0 ) return 0x03f00000; // Rd = #Ii (6 bits)
    if( (word & 0xff000000) == 0x48000000 ) return 0x061f20ff; // gp store
    if( (word & 0xff000000) == 0x49000000 ) return 0x061f3fe0; // gp load
    if( (word & 0xff000000) == 0x78000000 ) return 0x00df3fe0; // Rd = #Ii
    if( (word & 0xff000000) == 0xb0000000 ) return 0x0fe03fe0; // Rd = add(Rs,#Ii)
    if( (word & 0xff000000) == 0x7e000000 ) return 0x000f1fe0; // if(pu) Rd = #Ii (12 bits)
    warning( "unrecognized instruction for R_HEX_16_X relocation: 0x%08X\n", word );
    return 0;
}

static uint32_t apply_mask( uint32_t v, uint32_t mask )
{
    uint32_t out = 0;
    for( uint32_t m = 1; m; m <<= 1 )
    {
        if( (mask & m) ) out |= v & m;
        else v <<= 1;
    }
    return out;
}

//
// apply ELF relocations to the loaded instructions/data
// notes:
// 1) most of the functions provided by ELF loader are not accessible
//    because they are non-virtual and not exported by IDA
// 2) we process GOT/PLT relocations as if they we normal ones,
//    without creating any table entries
//
static const char* proc_relocation(
    reader_t &/*reader*/,
    const rel_data_t &rel_data,
    const sym_rel *symbol,
    const elf_rela_t* /*reloc*/,
    reloc_tools_t* /*tools*/
    )
{
    // msg( "rel @0x%X: type=%2d, Sadd=0x%X, S=0x%X, sym=%s\n",
    //      rel_data.P, rel_data.type, rel_data.Sadd, rel_data.S, symbol->original_name );
    fixup_type_t ftype = FIXUP_OFF32;

    // simple cases
    switch( rel_data.type )
    {
    case R_HEX_32:
    case R_HEX_GLOB_DAT:
    case R_HEX_GOTREL_32:
    case R_HEX_JMP_SLOT:
    case R_HEX_RELATIVE:
        put_dword( rel_data.P, rel_data.Sadd );
        goto __fixup;
    case R_HEX_16:
        put_word( rel_data.P, rel_data.Sadd );
        goto __fixup;
    case R_HEX_8:
        put_byte( rel_data.P, rel_data.Sadd );
        goto __fixup;
    case R_HEX_HL16:
        put_dword( rel_data.P, get_dword( rel_data.P ) |
                   apply_mask( rel_data.Sadd >> 16, LO_MASK ) );
        put_dword( rel_data.P + 4, get_dword( rel_data.P + 4 ) |
                   apply_mask( rel_data.Sadd, LO_MASK ) );
        goto __fixup;
    }

    // word32 masked relocs
    uint32_t word = get_dword( rel_data.P ), value, mask;
    switch( rel_data.type )
    {
    // fixed pattern types
    case R_HEX_B22_PCREL:
    case R_HEX_PLT_B22_PCREL:
    case R_HEX_GD_PLT_B22_PCREL:
    case R_HEX_LD_PLT_B22_PCREL:
        value = int32_t(rel_data.Sadd - rel_data.P) >> 2, mask = B22_MASK;
        break;
    case R_HEX_B22_PCREL_X:
        value = (rel_data.Sadd - rel_data.P) & 0x3F, mask = B22_MASK;
        break;
    case R_HEX_B15_PCREL:
        value = int32_t(rel_data.Sadd - rel_data.P) >> 2, mask = B15_MASK;
        break;
    case R_HEX_B15_PCREL_X:
        value = (rel_data.Sadd - rel_data.P) & 0x3F, mask = B15_MASK;
        break;
    case R_HEX_B13_PCREL:
        value = int32_t(rel_data.Sadd - rel_data.P) >> 2, mask = B13_MASK;
        break;
    case R_HEX_B13_PCREL_X:
        value = (rel_data.Sadd - rel_data.P) & 0x3F, mask = B13_MASK;
        break;
    case R_HEX_B9_PCREL:
        value = int32_t(rel_data.Sadd - rel_data.P) >> 2, mask = B9_MASK;
        break;
    case R_HEX_B9_PCREL_X:
        value = (rel_data.Sadd - rel_data.P) & 0x3F, mask = B9_MASK;
        break;
    case R_HEX_B7_PCREL:
        value = int32_t(rel_data.Sadd - rel_data.P) >> 2, mask = B7_MASK;
        break;
    case R_HEX_B7_PCREL_X:
        value = (rel_data.Sadd - rel_data.P) & 0x3F, mask = B7_MASK;
        break;
    case R_HEX_B32_PCREL_X:
        value = int32_t(rel_data.Sadd - rel_data.P) >> 6, mask = X26_MASK;
        break;
    case R_HEX_LO16:
    case R_HEX_GOTREL_LO16:
        value = rel_data.Sadd, mask = LO_MASK, ftype = FIXUP_LOW16;
        break;
    case R_HEX_HI16:
    case R_HEX_GOTREL_HI16:
        value = rel_data.Sadd >> 16, mask = LO_MASK, ftype = FIXUP_HI16;
        break;
    case R_HEX_32_PCREL:
        value = rel_data.Sadd - rel_data.P, mask = 0xffffffff;
        break;
    case R_HEX_32_6_X:
    case R_HEX_GOT_32_6_X:
    case R_HEX_GOTREL_32_6_X:
    case R_HEX_GD_GOT_32_6_X:
        value = rel_data.Sadd >> 6, mask = X26_MASK;
        break;
    case R_HEX_12_X:
        value = rel_data.Sadd, mask = R6_MASK;
        break;

    // variable pattern types (GP/U6/U16)
    case R_HEX_GPREL16_0:
        value = rel_data.Sadd - _SDA_BASE_, mask = get_mask_R16( word );
        break;
    case R_HEX_GPREL16_1:
        value = (rel_data.Sadd - _SDA_BASE_) >> 1, mask = get_mask_R16( word );
        break;
    case R_HEX_GPREL16_2:
        value = (rel_data.Sadd - _SDA_BASE_) >> 2, mask = get_mask_R16( word );
        break;
    case R_HEX_GPREL16_3:
        value = (rel_data.Sadd - _SDA_BASE_) >> 3, mask = get_mask_R16( word );
        break;
    case R_HEX_16_X:
    case R_HEX_GOT_16_X:
    case R_HEX_GOTREL_16_X:
    case R_HEX_GD_GOT_16_X:
        value = rel_data.Sadd, mask = get_mask_R16( word );
        break;
    case R_HEX_11_X:
    case R_HEX_GOT_11_X:
    case R_HEX_GOTREL_11_X:
    case R_HEX_GD_GOT_11_X:
        value = rel_data.Sadd, mask = get_mask_R11( word );
        break;
    case R_HEX_10_X:
        value = rel_data.Sadd, mask = 0x00203fe0;
        break;
    case R_HEX_9_X:
        value = rel_data.Sadd, mask = 0x00003fe0;
        break;
    case R_HEX_8_X:
        value = rel_data.Sadd, mask = get_mask_R8( word );
        break;
    case R_HEX_6_X:
        value = rel_data.Sadd, mask = get_mask_R6( word );
        break;
    case R_HEX_6_PCREL_X:
        value = rel_data.Sadd - rel_data.P, mask = get_mask_R6( word );
        break;

    // the rest is not implemented yet
    default: __fail:
        msg( "Couldn't relocate @0x%X: type=%2d, Sadd=0x%X, S=0x%X, symbol='%s'\n",
             rel_data.P, rel_data.type, rel_data.Sadd, rel_data.S, symbol->original_name );
        return E_RELOC_UNKNOWN;
    }

    // check if mask is correct
    if( !mask || (word & mask) ) goto __fail;
    word |= apply_mask( value, mask );
    put_dword( rel_data.P, word );

__fixup:
    // add a fixup
    fixup_data_t fd( ftype );
    fd.off = rel_data.Sadd;
    fd.set( rel_data.P );
    return NULL; // ok
}

static const char* proc_dynamic_tag( reader_t &reader, const Elf64_Dyn *dyn )
{
    switch( dyn->d_tag )
    {
    case DT_NEEDED:      return "Uses        :";
    case DT_SONAME:      return "Library name:";
    case DT_PLTGOT:      _GOT_ = dyn->d_un; break;
    case DT_HEXAGON_PLT: _PLT_ = dyn->d_un; break;
    }
    return NULL;
}

static proc_def_t hexagon_proc = {
    0,
    proc_relocation,            // must be implemented
    NULL,                       // proc_patch,
    proc_flag,
    NULL,                       // stubname
    NULL,                       // proc_sec_ext
    NULL,                       // proc_sym_ext
    proc_dynamic_tag,           // proc_dyn_ext
    NULL,                       // proc_file_ext,
    NULL,                       // proc_start_ext,
    NULL,                       // proc_post_process,
    NULL,                       // proc_sym_init,
    NULL,                       // proc_sym_handle,
    0,                          // patch_mode (set by IDA)
    0,                          // r_drop
    0,                          // r_gotset
    R_HEX_JMP_SLOT,             // r_err
    R_HEX_GLOB_DAT,             // r_chk
    { 0 },                      // relsyms (what do we put here?)
    NULL,                       // proc_sect_check
    NULL,                       // proc_sect_handle
    NULL,                       // calc_procname
    { 0 },                      // relsecord
    NULL,                       // proc_entry_handle
    { 0 },                      // additional_spec_secidx
    0,                          // tls_tcb_size
    0,                          // tls_tcb_align
};

// ELF loader machine type checkpoint
ssize_t loader_elf_machine( linput_t*, int machine_type, const char**, proc_def_t **p_pd )
{
    // tell ELF loader to use our mini-plugin for processor-specific stuff
    assert( machine_type == EM_QDSP6 );
    *p_pd = &hexagon_proc;
    return machine_type;
}
