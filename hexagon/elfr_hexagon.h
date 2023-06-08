#ifndef __ELFR_HEXAGON_H__
#define __ELFR_HEXAGON_H__

#ifndef __ELFBASE_H__
#include "elfbase.h"
#endif

enum
{
    // relocation types
    R_HEX_NONE                = 0,
    R_HEX_B22_PCREL           = 1,
    R_HEX_B15_PCREL           = 2,
    R_HEX_B7_PCREL            = 3,
    R_HEX_LO16                = 4,
    R_HEX_HI16                = 5,
    R_HEX_32                  = 6,
    R_HEX_16                  = 7,
    R_HEX_8                   = 8,
    R_HEX_GPREL16_0           = 9,
    R_HEX_GPREL16_1           = 10,
    R_HEX_GPREL16_2           = 11,
    R_HEX_GPREL16_3           = 12,
    R_HEX_HL16                = 13,
    R_HEX_B13_PCREL           = 14,
    R_HEX_B9_PCREL            = 15,
    R_HEX_B32_PCREL_X         = 16,
    R_HEX_32_6_X              = 17,
    R_HEX_B22_PCREL_X         = 18,
    R_HEX_B15_PCREL_X         = 19,
    R_HEX_B13_PCREL_X         = 20,
    R_HEX_B9_PCREL_X          = 21,
    R_HEX_B7_PCREL_X          = 22,
    R_HEX_16_X                = 23,
    R_HEX_12_X                = 24,
    R_HEX_11_X                = 25,
    R_HEX_10_X                = 26,
    R_HEX_9_X                 = 27,
    R_HEX_8_X                 = 28,
    R_HEX_7_X                 = 29,
    R_HEX_6_X                 = 30,
    R_HEX_32_PCREL            = 31,
    R_HEX_COPY                = 32,
    R_HEX_GLOB_DAT            = 33,
    R_HEX_JMP_SLOT            = 34,
    R_HEX_RELATIVE            = 35,
    R_HEX_PLT_B22_PCREL       = 36,
    R_HEX_GOTREL_LO16         = 37,
    R_HEX_GOTREL_HI16         = 38,
    R_HEX_GOTREL_32           = 39,
    R_HEX_GOT_LO16            = 40,
    R_HEX_GOT_HI16            = 41,
    R_HEX_GOT_32              = 42,
    R_HEX_GOT_16              = 43,
    R_HEX_DTPMOD_32           = 44,
    R_HEX_DTPREL_LO16         = 45,
    R_HEX_DTPREL_HI16         = 46,
    R_HEX_DTPREL_32           = 47,
    R_HEX_DTPREL_16           = 48,
    R_HEX_GD_PLT_B22_PCREL    = 49,
    R_HEX_GD_GOT_LO16         = 50,
    R_HEX_GD_GOT_HI16         = 51,
    R_HEX_GD_GOT_32           = 52,
    R_HEX_GD_GOT_16           = 53,
    R_HEX_IE_LO16             = 54,
    R_HEX_IE_HI16             = 55,
    R_HEX_IE_32               = 56,
    R_HEX_IE_GOT_LO16         = 57,
    R_HEX_IE_GOT_HI16         = 58,
    R_HEX_IE_GOT_32           = 59,
    R_HEX_IE_GOT_16           = 60,
    R_HEX_TPREL_LO16          = 61,
    R_HEX_TPREL_HI16          = 62,
    R_HEX_TPREL_32            = 63,
    R_HEX_TPREL_16            = 64,
    R_HEX_6_PCREL_X           = 65,
    R_HEX_GOTREL_32_6_X       = 66,
    R_HEX_GOTREL_16_X         = 67,
    R_HEX_GOTREL_11_X         = 68,
    R_HEX_GOT_32_6_X          = 69,
    R_HEX_GOT_16_X            = 70,
    R_HEX_GOT_11_X            = 71,
    R_HEX_DTPREL_32_6_X       = 72,
    R_HEX_DTPREL_16_X         = 73,
    R_HEX_DTPREL_11_X         = 74,
    R_HEX_GD_GOT_32_6_X       = 75,
    R_HEX_GD_GOT_16_X         = 76,
    R_HEX_GD_GOT_11_X         = 77,
    R_HEX_IE_32_6_X           = 78,
    R_HEX_IE_16_X             = 79,
    R_HEX_IE_GOT_32_6_X       = 80,
    R_HEX_IE_GOT_16_X         = 81,
    R_HEX_IE_GOT_11_X         = 82,
    R_HEX_TPREL_32_6_X        = 83,
    R_HEX_TPREL_16_X          = 84,
    R_HEX_TPREL_11_X          = 85,
    R_HEX_LD_PLT_B22_PCREL    = 86,
    R_HEX_LD_GOT_LO16         = 87,
    R_HEX_LD_GOT_HI16         = 88,
    R_HEX_LD_GOT_32           = 89,
    R_HEX_LD_GOT_16           = 90,
    R_HEX_LD_GOT_32_6_X       = 91,
    R_HEX_LD_GOT_16_X         = 92,
    R_HEX_LD_GOT_11_X         = 93,
    R_HEX_23_REG              = 94,
    R_HEX_GD_PLT_B22_PCREL_X  = 95,
    R_HEX_GD_PLT_B32_PCREL_X  = 96,
    R_HEX_LD_PLT_B22_PCREL_X  = 97,
    R_HEX_LD_PLT_B32_PCREL_X  = 98,
    R_HEX_27_REG              = 99,

    // processor specific flags for the ELF header e_flags[11:0] field
    EF_HEXAGON_MACH_V4        = 0x3,    // Hexagon V4
    EF_HEXAGON_MACH_V5        = 0x4,    // Hexagon V5
    EF_HEXAGON_MACH_V55       = 0x5,    // Hexagon V55
    EF_HEXAGON_MACH_V60       = 0x60,   // Hexagon V60
    EF_HEXAGON_MACH_V61       = 0x61,   // Hexagon V61
    EF_HEXAGON_MACH_V62       = 0x62,   // Hexagon V62
    EF_HEXAGON_MACH_V65       = 0x65,   // Hexagon V65
    EF_HEXAGON_MACH_V66       = 0x66,   // Hexagon V66
    EF_HEXAGON_MACH_V67       = 0x67,   // Hexagon V67
    EF_HEXAGON_MACH_V67T      = 0x8067, // Hexagon V67 Small Core (V67t)
    EF_HEXAGON_MACH_V68       = 0x68,   // Hexagon V68
    EF_HEXAGON_MACH_V69       = 0x69,   // Hexagon V69
    EF_HEXAGON_MACH_V71       = 0x71,   // Hexagon V71
    EF_HEXAGON_MACH_V73       = 0x73,   // Hexagon V73

    // processor specific dynamic array tags
    DT_HEXAGON_SYMSZ          = 0x70000000,
    DT_HEXAGON_VER            = 0x70000001,
    DT_HEXAGON_PLT            = 0x70000002,
};

#endif // __ELFR_HEXAGON_H__
