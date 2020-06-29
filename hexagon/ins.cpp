/*------------------------------------------------------------------------------

  Copyright (c) n-o-o-n (n_o_o_n@bk.ru)
  All rights reserved.

------------------------------------------------------------------------------*/
#include "common.h"

static const char *const insn_template[] = {
    "",                                     // Hex_NONE
    "%0=abs(%1)",                           // Hex_abs
    "%0=add(%1, %2)",                       // Hex_add
    "%0=add(%1, add(%2, %3))",              // Hex_add_add
    "%0=add(%1, asl(%0, %2))",              // Hex_add_asl
    "%0=add(clb(%1), %2)",                  // Hex_add_clb
    "%0=add(%1, lsr(%0, %2))",              // Hex_add_lsr
    "%0=add(%1, mpyi(%2, %3))",             // Hex_add_mpyi
    "%0=add(%1, sub(%3, %2))",              // Hex_add_sub
    "%0=addasl(%2, %1, %3)",                // Hex_addasl
    "%0=add(%1, %2, %3)",                   // Hex_addc
    "%0=all8(%1)",                          // Hex_all8
    "%0=and(%1, %2)",                       // Hex_and
    "%0=and(%1, and(%2, %3))",              // Hex_and_and
    "%0=and(%1, asl(%0, %2))",              // Hex_and_asl
    "%0=and(%1, lsr(%0, %2))",              // Hex_and_lsr
    "%0=and(%1, or(%2, %3))",               // Hex_and_or
    "%0=any8(%1)",                          // Hex_any8
    "%0=asl(%1, %2)",                       // Hex_asl
    "%0=aslh(%1)",                          // Hex_aslh
    "%0=asr(%1, %2)",                       // Hex_asr
    "%0=asrh(%1)",                          // Hex_asrh
    "%0=bitsclr(%1, %2)",                   // Hex_bitsclr
    "%0=bitsplit(%1, %2)",                  // Hex_bitsplit
    "%0=bitsset(%1, %2)",                   // Hex_bitsset
    "%0=boundscheck(%1, %2)",               // Hex_boundscheck
    "%0=brev(%1)",                          // Hex_brev
    "%0=cl0(%1)",                           // Hex_cl0
    "%0=cl1(%1)",                           // Hex_cl1
    "%0=clb(%1)",                           // Hex_clb
    "%0=clip(%1, %2)",                      // Hex_clip
    "%0=clrbit(%1)",                        // Hex_clrbit
    "%0=clrbit(%1, %2)",                    // Hex_clrbit2
    "%0=cmp%s%c(%1, %2)",                   // Hex_cmp
    "%0=combine(%1, %2)",                   // Hex_combine
    "%0=cround(%1, %2)",                    // Hex_cround
    "%0=ct0(%1)",                           // Hex_ct0
    "%0=ct1(%1)",                           // Hex_ct1
    "%0=decbin(%1, %2)",                    // Hex_decbin
    "%0=deinterleave(%1)",                  // Hex_deinterleave
    "%0=extract(%1, %2)",                   // Hex_extract
    "%0=extract(%1, %2, %3)",               // Hex_extract3
    "%0=extractu(%1, %2)",                  // Hex_extractu
    "%0=extractu(%1, %2, %3)",              // Hex_extractu3
    "%0=fastcorner9(%1, %2)",               // Hex_fastcorner9
    "%0=insert(%1, %2)",                    // Hex_insert
    "%0=insert(%1, %2, %3)",                // Hex_insert3
    "%0=interleave(%1)",                    // Hex_interleave
    "%0=lfs(%1, %2)",                       // Hex_lfs
    "%0=lsl(%1, %2)",                       // Hex_lsl
    "%0=lsr(%1, %2)",                       // Hex_lsr
    "%0=mask(%1)",                          // Hex_mask
    "%0=mask(%1, %2)",                      // Hex_mask2
    "%0=max(%1, %2)",                       // Hex_max
    "%0=maxu(%1, %2)",                      // Hex_maxu
    "memcpy(%0, %1, %2)",                   // Hex_memcpy
    "%0=min(%2, %1)",                       // Hex_min
    "%0=minu(%2, %1)",                      // Hex_minu
    "%0=modwrap(%1, %2)",                   // Hex_modwrap
    "%0=%1",                                // Hex_mov
    "%0=mux(%1, %2, %3)",                   // Hex_mux
    "%0=neg(%1)",                           // Hex_neg
    "nop",                                  // Hex_nop
    "%0=normamt(%1)",                       // Hex_normamt
    "%0=not(%1)",                           // Hex_not
    "%0=or(%1, %2)",                        // Hex_or
    "%0=or(%1, and(%2, %3))",               // Hex_or_and
    "%0=or(%1, asl(%0, %2))",               // Hex_or_asl
    "%0=or(%1, lsr(%0, %2))",               // Hex_or_lsr
    "%0=or(%1, or(%2, %3))",                // Hex_or_or
    "%0=packhl(%1, %2)",                    // Hex_packhl
    "%0=parity(%1, %2)",                    // Hex_parity
    "%0=popcount(%1)",                      // Hex_popcount
    "%0=rol(%1, %2)",                       // Hex_rol
    "%0=round(%1)",                         // Hex_round
    "%0=round(%1, %2)",                     // Hex_round2
    "%0=sat%s(%1)",                         // Hex_sat
    "%0=setbit(%1)",                        // Hex_setbit
    "%0=setbit(%1, %2)",                    // Hex_setbit2
    "%0=shuffeb(%1, %2)",                   // Hex_shuffeb
    "%0=shuffeh(%1, %2)",                   // Hex_shuffeh
    "%0=shuffob(%2, %1)",                   // Hex_shuffob
    "%0=shuffoh(%2, %1)",                   // Hex_shuffoh
    "%0=sub(%2, %1)",                       // Hex_sub
    "%0=sub(%1, asl(%0, %2))",              // Hex_sub_asl
    "%0=sub(%1, lsr(%0, %2))",              // Hex_sub_lsr
    "%0=sub(%1, %2, %3)",                   // Hex_subc
    "%0=swiz(%1)",                          // Hex_swiz
    "%0=sxtb(%1)",                          // Hex_sxtb
    "%0=sxth(%1)",                          // Hex_sxth
    "%0=sxtw(%1)",                          // Hex_sxtw
    "%0=tableidx%s(%1, %2, %3)",            // Hex_tableidx
    "%0=togglebit(%1, %2)",                 // Hex_togglebit
    "%0=tstbit(%1, %2)",                    // Hex_tstbit
    "%0=xor(%1, %2)",                       // Hex_xor
    "%0=zxtb(%1)",                          // Hex_zxtb
    "%0=zxth(%1)",                          // Hex_zxth
    // program flow
    "hintjr(%0)",                           // Hex_hintjr
    "call %0",                              // Hex_call
    "callr %0",                             // Hex_callr
    "jump%t %0",                            // Hex_jump
    "jumpr%t %0",                           // Hex_jumpr
    "%0=cmp%c(%1, %2);if (%3) jump%t %4",   // Hex_cmp_jump
    "%0=%1;jump %2",                        // Hex_set_jump
    "%0=tstbit(%1, %2);if (%3) jump%t %4",  // Hex_tstbit_jump
    "loop0(%0, %1)",                        // Hex_loop0
    "loop1(%0, %1)",                        // Hex_loop1
    "%0=sp1loop0(%1, %2)",                  // Hex_sp1loop0
    "%0=sp2loop0(%1, %2)",                  // Hex_sp2loop0
    "%0=sp3loop0(%1, %2)",                  // Hex_sp3loop0
    "allocframe(%0, %1):raw",               // Hex_allocframe_raw
    "allocframe(%0)",                       // Hex_allocframe
    "%0=deallocframe(%1):raw",              // Hex_deallocframe_raw
    "deallocframe",                         // Hex_deallocframe
    "%0=dealloc_return(%1)%t:raw",          // Hex_return_raw
    "dealloc_return%t",                     // Hex_return
    // system/user
    "barrier",                              // Hex_barrier
    "brkpt",                                // Hex_brkpt
    "dccleana(%0)",                         // Hex_dccleana
    "dccleaninva(%0)",                      // Hex_dccleaninva
    "dcfetch(%0)",                          // Hex_dcfetchbo
    "dcinva(%0)",                           // Hex_dcinva
    "dczeroa(%0)",                          // Hex_dczeroa
    "diag(%0)",                             // Hex_diag
    "diag0(%0, %1)",                        // Hex_diag0
    "diag1(%0, %1)",                        // Hex_diag1
    "icinva(%0)",                           // Hex_icinva
    "isync",                                // Hex_isync
    "l2fetch(%0, %1)",                      // Hex_l2fetch
    "pause(%0)",                            // Hex_pause
    "syncht",                               // Hex_syncht
    "%0=tlbmatch(%1, %2)",                  // Hex_tlbmatch
    "trace(%0)",                            // Hex_trace
    "trap0(%0)",                            // Hex_trap0
    "trap1(%0)",                            // Hex_trap1
    "trap1(%0, %1)",                        // Hex_trap1_2
    // system/monitor
    "ciad(%0)",                             // Hex_ciad
    "crswap(%0, %1)",                       // Hex_crswap
    "cswi(%0)",                             // Hex_cswi
    "%0=ctlbw(%1, %2)",                     // Hex_ctlbw
    "dccleanidx(%0)",                       // Hex_dccleanidx
    "dccleaninvidx(%0)",                    // Hex_dccleaninvidx
    "dcinvidx(%0)",                         // Hex_dcinvidx
    "dckill",                               // Hex_dckill
    "%0=dctagr(%1)",                        // Hex_dctagr
    "dctagw(%0, %1)",                       // Hex_dctagw
    "%0=getimask(%1)",                      // Hex_getimask
    "%0=iassignr(%1)",                      // Hex_iassignr
    "iassignw(%0)",                         // Hex_iassignw
    "%0=icdatar(%1)",                       // Hex_icdatar
    "icdataw(%0, %1)",                      // Hex_icdataw
    "icinvidx(%0)",                         // Hex_icinvidx
    "ickill",                               // Hex_ickill
    "%0=ictagr(%1)",                        // Hex_ictagr
    "ictagw(%0, %1)",                       // Hex_ictagw
    "k0lock",                               // Hex_k0lock
    "k0unlock",                             // Hex_k0unlock
    "l2cleanidx(%0)",                       // Hex_l2cleanidx
    "l2cleaninvidx(%0)",                    // Hex_l2cleaninvidx
    "l2gclean",                             // Hex_l2gclean
    "l2gclean(%0)",                         // Hex_l2gclean1
    "l2gcleaninv",                          // Hex_l2gcleaninv
    "l2gcleaninv(%0)",                      // Hex_l2gcleaninv1
    "l2gunlock",                            // Hex_l2gunlock
    "l2invidx(%0)",                         // Hex_l2invidx
    "l2kill",                               // Hex_l2kill
    "%0=l2locka(%1)",                       // Hex_l2locka
    "%0=l2tagr(%1)",                        // Hex_l2tagr
    "l2tagw(%0, %1)",                       // Hex_l2tagw
    "l2unlocka(%0)",                        // Hex_l2unlocka
    "%0=memw_phys(%1, %2)",                 // Hex_ldphys
    "nmi(%0)",                              // Hex_nmi
    "resume(%0)",                           // Hex_resume
    "rte",                                  // Hex_rte
    "setimask(%0, %1)",                     // Hex_setimask
    "setprio(%0, %1)",                      // Hex_setprio
    "siad(%0)",                             // Hex_siad
    "start(%0)",                            // Hex_start
    "stop(%0)",                             // Hex_stop
    "swi(%0)",                              // Hex_swi
    "tlbinvasid(%0)",                       // Hex_tlbinvasid
    "tlblock",                              // Hex_tlblock
    "%0=tlboc(%1)",                         // Hex_tlboc
    "%0=tlbp(%1)",                          // Hex_tlbp
    "%0=tlbr(%1)",                          // Hex_tlbr
    "tlbunlock",                            // Hex_tlbunlock
    "tlbw(%0, %1)",                         // Hex_tlbw
    "wait(%0)",                             // Hex_wait
    // multiplication
    "%0=cmpy(%1, %2)",                      // Hex_cmpy
    "%0=cmpyi(%1, %2)",                     // Hex_cmpyi
    "%0=cmpyiw(%1, %2)",                    // Hex_cmpyiw
    "%0=cmpyiwh(%1, %2)",                   // Hex_cmpyiwh
    "%0=cmpyr(%1, %2)",                     // Hex_cmpyr
    "%0=cmpyrw(%1, %2)",                    // Hex_cmpyrw
    "%0=cmpyrwh(%1, %2)",                   // Hex_cmpyrwh
    "%0=mpy(%1, %2)",                       // Hex_mpy
    "%0=mpyi(%1, %2)",                      // Hex_mpyi
    "%0=mpysu(%1, %2)",                     // Hex_mpysu
    "%0=mpyu(%1, %2)",                      // Hex_mpyu
    "%0=pmpyw(%1, %2)",                     // Hex_pmpyw
    // floating point
    "%0=convert_d2df(%1)",                  // Hex_conv_d2df
    "%0=convert_d2sf(%1)",                  // Hex_conv_d2sf
    "%0=convert_df2d(%1)",                  // Hex_conv_df2d
    "%0=convert_df2sf(%1)",                 // Hex_conv_df2sf
    "%0=convert_df2ud(%1)",                 // Hex_conv_df2ud
    "%0=convert_df2uw(%1)",                 // Hex_conv_df2uw
    "%0=convert_df2w(%1)",                  // Hex_conv_df2w
    "%0=convert_sf2d(%1)",                  // Hex_conv_sf2d
    "%0=convert_sf2df(%1)",                 // Hex_conv_sf2df
    "%0=convert_sf2ud(%1)",                 // Hex_conv_sf2ud
    "%0=convert_sf2uw(%1)",                 // Hex_conv_sf2uw
    "%0=convert_sf2w(%1)",                  // Hex_conv_sf2w
    "%0=convert_ud2df(%1)",                 // Hex_conv_ud2df
    "%0=convert_ud2sf(%1)",                 // Hex_conv_ud2sf
    "%0=convert_uw2df(%1)",                 // Hex_conv_uw2df
    "%0=convert_uw2sf(%1)",                 // Hex_conv_uw2sf
    "%0=convert_w2df(%1)",                  // Hex_conv_w2df
    "%0=convert_w2sf(%1)",                  // Hex_conv_w2sf
    "%0=dfadd(%1, %2)",                     // Hex_dfadd
    "%0=dfclass(%1, %2)",                   // Hex_dfclass
    "%0=dfcmp%c(%1, %2)",                   // Hex_dfcmp
    "%0=dfmake(%1)",                        // Hex_dfmake
    "%0=dfmax(%1, %2)",                     // Hex_dfmax
    "%0=dfmin(%1, %2)",                     // Hex_dfmin
    "%0=dfmpyfix(%1, %2)",                  // Hex_dfmpyfix
    "%0=dfmpyhh(%1, %2)",                   // Hex_dfmpyhh
    "%0=dfmpylh(%1, %2)",                   // Hex_dfmpylh
    "%0=dfmpyll(%1, %2)",                   // Hex_dfmpyll
    "%0=dfsub(%1, %2)",                     // Hex_dfsub
    "%0=sfadd(%1, %2)",                     // Hex_sfadd
    "%0=sfclass(%1, %2)",                   // Hex_sfclass
    "%0=sfcmp%c(%1, %2)",                   // Hex_sfcmp
    "%0=sffixupd(%1, %2)",                  // Hex_sffixupd
    "%0=sffixupn(%1, %2)",                  // Hex_sffixupn
    "%0=sffixupr(%1)",                      // Hex_sffixupr
    "%0, %1=sfinvsqrta(%2)",                // Hex_sfinvsqrta
    "%0=sfmake(%1)",                        // Hex_sfmake
    "%0=sfmax(%1, %2)",                     // Hex_sfmax
    "%0=sfmin(%1, %2)",                     // Hex_sfmin
    "%0=sfmpy(%1, %2)",                     // Hex_sfmpy
    "%0=sfmpy(%1, %2, %3)",                 // Hex_sfmpy3
    "%0, %1=sfrecipa(%2, %3)",              // Hex_sfrecipa
    "%0=sfsub(%1, %2)",                     // Hex_sfsub
    // vector
    "%0=vabsdiff%s(%2, %1)",                // Hex_svabsdiff
    "%0=vabsh(%1)",                         // Hex_svabsh
    "%0=vabsw(%1)",                         // Hex_svabsw
    "%0, %1=vacsh(%2, %3)",                 // Hex_svacsh
    "%0=vaddh(%1, %2)",                     // Hex_svaddh
    "%0=vaddhub(%1, %2)",                   // Hex_svaddhub
    "%0=vaddub(%1, %2)",                    // Hex_svaddub
    "%0=vadduh(%1, %2)",                    // Hex_svadduh
    "%0=vaddw(%1, %2)",                     // Hex_svaddw
    "%0=valignb(%2, %1, %3)",               // Hex_svalignb
    "%0=vaslh(%1, %2)",                     // Hex_svaslh
    "%0=vaslw(%1, %2)",                     // Hex_svaslw
    "%0=vasrh(%1, %2)",                     // Hex_svasrh
    "%0=vasrhub(%1, %2)",                   // Hex_svasrhub
    "%0=vasrw(%1, %2)",                     // Hex_svasrw
    "%0=vavg%s(%1, %2)",                    // Hex_svavg
    "%0=vclip(%1, %2)",                     // Hex_svclip
    "%0=vcmp%s%c(%1, %2)",                  // Hex_svcmp
    "%0=any8(vcmpb%c(%1, %2))",             // Hex_svcmpbeq_any
    "%0=vcmpyi(%1, %2)",                    // Hex_svcmpyi
    "%0=vcmpyr(%1, %2)",                    // Hex_svcmpyr
    "%0=vcnegh(%1, %2)",                    // Hex_svcnegh
    "%0=vconj(%1)",                         // Hex_svconj
    "%0=vcrotate(%1, %2)",                  // Hex_svcrotate
    "%0=vdmpy(%1, %2)",                     // Hex_svdmpy
    "%0=vdmpybsu(%1, %2)",                  // Hex_svdmpybsu
    "%0=vitpack(%1, %2)",                   // Hex_svitpack
    "%0=vlslh(%1, %2)",                     // Hex_svlslh
    "%0=vlslw(%1, %2)",                     // Hex_svlslw
    "%0=vlsrh(%1, %2)",                     // Hex_svlsrh
    "%0=vlsrw(%1, %2)",                     // Hex_svlsrw
    "%0=vmaxb(%2, %1)",                     // Hex_svmaxb
    "%0=vmaxh(%2, %1)",                     // Hex_svmaxh
    "%0=vmaxub(%2, %1)",                    // Hex_svmaxub
    "%0=vmaxuh(%2, %1)",                    // Hex_svmaxuh
    "%0=vmaxuw(%2, %1)",                    // Hex_svmaxuw
    "%0=vmaxw(%2, %1)",                     // Hex_svmaxw
    "%0=vminb(%2, %1)",                     // Hex_svminb
    "%0=vminh(%2, %1)",                     // Hex_svminh
    "%0=vminub(%2, %1)",                    // Hex_svminub
    "%0, %1=vminub(%3, %2)",                // Hex_svminub2d
    "%0=vminuh(%2, %1)",                    // Hex_svminuh
    "%0=vminuw(%2, %1)",                    // Hex_svminuw
    "%0=vminw(%2, %1)",                     // Hex_svminw
    "%0=vmpybsu(%1, %2)",                   // Hex_svmpybsu
    "%0=vmpybu(%1, %2)",                    // Hex_svmpybu
    "%0=vmpyeh(%1, %2)",                    // Hex_svmpyeh
    "%0=vmpyh(%1, %2)",                     // Hex_svmpyh
    "%0=vmpyhsu(%1, %2)",                   // Hex_svmpyhsu
    "%0=vmpyweh(%1, %2)",                   // Hex_svmpyweh
    "%0=vmpyweuh(%1, %2)",                  // Hex_svmpyweuh
    "%0=vmpywoh(%1, %2)",                   // Hex_svmpywoh
    "%0=vmpywouh(%1, %2)",                  // Hex_svmpywouh
    "%0=vmux(%1, %2, %3)",                  // Hex_svmux
    "%0=vnavg%s(%2, %1)",                   // Hex_svnavg
    "%0=vpmpyh(%1, %2)",                    // Hex_svpmpyh
    "%0=vraddh(%1, %2)",                    // Hex_svraddh
    "%0=vraddub(%1, %2)",                   // Hex_svraddub
    "%0=vradduh(%1, %2)",                   // Hex_svradduh
    "%0=vrcmpyi(%1, %2)",                   // Hex_svrcmpyi
    "%0=vrcmpyr(%1, %2)",                   // Hex_svrcmpyr
    "%0=vrcmpys(%1, %2)",                   // Hex_svrcmpys
    "%0=vrcnegh(%1, %2)",                   // Hex_svrcnegh
    "%0=vrcrotate(%1, %2, %3)",             // Hex_svrcrotate
    "%0=vrmax%s(%1, %2)",                   // Hex_svrmax
    "%0=vrmin%s(%1, %2)",                   // Hex_svrmin
    "%0=vrmpybsu(%1, %2)",                  // Hex_svrmpybsu
    "%0=vrmpybu(%1, %2)",                   // Hex_svrmpybu
    "%0=vrmpyh(%1, %2)",                    // Hex_svrmpyh
    "%0=vrmpyweh(%1, %2)",                  // Hex_svrmpyweh
    "%0=vrmpywoh(%1, %2)",                  // Hex_svrmpywoh
    "%0=vrndwh(%1)",                        // Hex_svrndwh
    "%0=vrsadub(%1, %2)",                   // Hex_svrsadub
    "%0=vsathb(%1)",                        // Hex_svsathb
    "%0=vsathub(%1)",                       // Hex_svsathub
    "%0=vsatwh(%1)",                        // Hex_svsatwh
    "%0=vsatwuh(%1)",                       // Hex_svsatwuh
    "%0=vsplatb(%1)",                       // Hex_svsplatb
    "%0=vsplath(%1)",                       // Hex_svsplath
    "%0=vspliceb(%1, %2, %3)",              // Hex_svspliceb
    "%0=vsubh(%2, %1)",                     // Hex_svsubh
    "%0=vsubub(%2, %1)",                    // Hex_svsubub
    "%0=vsubuh(%2, %1)",                    // Hex_svsubuh
    "%0=vsubw(%2, %1)",                     // Hex_svsubw
    "%0=vsxtbh(%1)",                        // Hex_svsxtbh
    "%0=vsxthw(%1)",                        // Hex_svsxthw
    "%0=vtrunehb(%1)",                      // Hex_svtrunehb
    "%0=vtrunehb(%1, %2)",                  // Hex_svtrunehb2
    "%0=vtrunewh(%1, %2)",                  // Hex_svtrunewh
    "%0=vtrunohb(%1)",                      // Hex_svtrunohb
    "%0=vtrunohb(%1, %2)",                  // Hex_svtrunohb2
    "%0=vtrunowh(%1, %2)",                  // Hex_svtrunowh
    "%0=vxaddsubh(%1, %2)",                 // Hex_svxaddsubh
    "%0=vxaddsubw(%1, %2)",                 // Hex_svxaddsubw
    "%0=vxsubaddh(%1, %2)",                 // Hex_svxsubaddh
    "%0=vxsubaddw(%1, %2)",                 // Hex_svxsubaddw
    "%0=vzxtbh(%1)",                        // Hex_svzxtbh
    "%0=vzxthw(%1)",                        // Hex_svzxthw
    // HVX
    "%0=prefixsum(%1)",                     // Hex_prefixsum
    "%0=vabs(%1)",                          // Hex_vabs
    "%0=vabsdiff(%1, %2)",                  // Hex_vabsdiff
    "%0=vadd(%1, %2)",                      // Hex_vadd
    "%0=vadd(%1, %2, %3)",                  // Hex_vadd3
    "%0, %1=vadd(%2, %3)",                  // Hex_vadd2d
    "%0=vadd(vclb(%1), %2)",                // Hex_vaddclb
    "%0=valign(%1, %2, %3)",                // Hex_valign
    "%0=vand(%1, %2)",                      // Hex_vand
    "%0=vasl(%1, %2)",                      // Hex_vasl
    "%0=vasr(%1, %2)",                      // Hex_vasr
    "%0=vasr(%1, %2, %3)",                  // Hex_vasr3
    "%0=vasrinto(%1, %2)",                  // Hex_vasrinto
    "%0=vavg(%1, %2)",                      // Hex_vavg
    "%0=vcombine(%1, %2)",                  // Hex_vcombine
    "%0=vcl0(%1)",                          // Hex_vcl0
    "%0=vcmp%c(%1, %2)",                    // Hex_vcmp
    "%0=vdeal(%1)",                         // Hex_vdeal
    "vdeal(%0, %1, %2)",                    // Hex_vdeal3
    "%0=vdeal(%1, %2, %3)",                 // Hex_vdeal4
    "%0=vdeale(%1, %2)",                    // Hex_vdeale
    "%0=vdelta(%1, %2)",                    // Hex_vdelta
    "%0=vdmpy(%1, %2)",                     // Hex_vdmpy
    "%0=vdmpy(%1, %2, %3)",                 // Hex_vdmpy3
    "%0=vdsad(%1, %2)",                     // Hex_vdsad
    "%0=vextract(%1, %2)",                  // Hex_vextract
    "%0=vgather(%1, %2, %3)%g",             // Hex_vgather
    "vhist",                                // Hex_vhist
    "vhist(%0)",                            // Hex_vhist1
    "%0=vinsert(%1)",                       // Hex_vinsert
    "%0=vlalign(%1, %2, %3)",               // Hex_vlalign
    "%0=vlsr(%1, %2)",                      // Hex_vlsr
    "%0=vlut16(%1, %2, %3)",                // Hex_vlut16
    "%0=vlut32(%1, %2, %3)",                // Hex_vlut32
    "%0=vlut4(%1, %2)",                     // Hex_vlut4
    "%0=vmax(%1, %2)",                      // Hex_vmax
    "%0=vmin(%1, %2)",                      // Hex_vmin
    "%0=vmpa(%1, %2)",                      // Hex_vmpa
    "%0=vmpa(%0, %1, %2)",                  // Hex_vmpa3
    "%0=vmps(%0, %1, %2)",                  // Hex_vmps
    "%0=vmpy(%1, %2)",                      // Hex_vmpy
    "%0=vmpye(%1, %2)",                     // Hex_vmpye
    "%0=vmpyi(%1, %2)",                     // Hex_vmpyi
    "%0=vmpyie(%1, %2)",                    // Hex_vmpyie
    "%0=vmpyieo(%1, %2)",                   // Hex_vmpyieo
    "%0=vmpyio(%1, %2)",                    // Hex_vmpyio
    "%0=vmpyo(%1, %2)",                     // Hex_vmpyo
    "%0=vmux(%1, %2, %3)",                  // Hex_vmux
    "%0=vnavg(%1, %2)",                     // Hex_vnavg
    "%0=vnormamt(%1)",                      // Hex_vnormamt
    "%0=vnot(%1)",                          // Hex_vnot
    "%0=vor(%1, %2)",                       // Hex_vor
    "%0=vpack(%1, %2)",                     // Hex_vpack
    "%0=vpacke(%1, %2)",                    // Hex_vpacke
    "%0=vpacko(%1, %2)",                    // Hex_vpacko
    "%0=vpopcount(%1)",                     // Hex_vpopcount
    "%0=vrdelta(%1, %2)",                   // Hex_vrdelta
    "%0=vrmpy(%1, %2)",                     // Hex_vrmpy
    "%0=vrmpy(%1, %2, %3)",                 // Hex_vrmpy3
    "%0=vror(%1, %2)",                      // Hex_vror
    "%0=vrotr(%1, %2)",                     // Hex_vrotr
    "%0=vround(%1, %2)",                    // Hex_vround
    "%0=vrsad(%1, %2, %3)",                 // Hex_vrsad
    "%0=vsat(%1, %2)",                      // Hex_vsat
    "%0=vsatdw(%1, %2)",                    // Hex_vsatdw
    "vscatter(%0, %1, %2)%g=%3",            // Hex_vscatter
    "%0:scatter_release",                   // Hex_vscatterrls
    "%0=vsetq(%1)",                         // Hex_vsetq
    "%0=vsetq2(%1)",                        // Hex_vsetq2
    "%0=vshuff(%1)",                        // Hex_vshuff
    "vshuff(%0, %1, %2)",                   // Hex_vshuff3
    "%0=vshuff(%1, %2, %3)",                // Hex_vshuff4
    "%0=vshuffe(%1, %2)",                   // Hex_vshuffe
    "%0=vshuffo(%1, %2)",                   // Hex_vshuffo
    "%0=vshuffoe(%1, %2)",                  // Hex_vshuffoe
    "%0=vsplat(%1)",                        // Hex_vsplat
    "%0=vsub(%1, %2)",                      // Hex_vsub
    "%0=vsub(%1, %2, %3)",                  // Hex_vsub3
    "%0, %1=vsub(%2, %3)",                  // Hex_vsub2d
    "%0=vswap(%1, %2, %3)",                 // Hex_vswap
    "%0=vsxt(%1)",                          // Hex_vsxt
    "%0=vtmpy(%1, %2)",                     // Hex_vtmpy
    "%0=vunpack(%1)",                       // Hex_vunpack
    "%0=vunpacko(%1)",                      // Hex_vunpacko
    "vwhist128",                            // Hex_vwhist128
    "vwhist128(%0)",                        // Hex_vwhist128_1
    "vwhist128(%0, %1)",                    // Hex_vwhist128_2
    "vwhist256",                            // Hex_vwhist256
    "vwhist256(%0)",                        // Hex_vwhist256_1
    "%0=vxor(%1, %2)",                      // Hex_vxor
    "%0=vzxt(%1)",                          // Hex_vzxt
    // HVX V66 AI extension
    "%0=vr16mpyz(%1, %2)",                  // Hex_vr16mpyz
    "%0=vr16mpyzs(%1, %2)",                 // Hex_vr16mpyzs
    "%0=vr8mpyz(%1, %2)",                   // Hex_vr8mpyz
    "%0=vrmpyz(%1, %2)",                    // Hex_vrmpyz
    "%0=zextract(%1)",                      // Hex_zextract
};

static_assert( _countof(insn_template) == Hex_NUM_INSN, "some strings are missing..." );

const char *get_insn_template( uint32_t itype )
{
    return itype < _countof(insn_template)? insn_template[itype] : "???";
}
