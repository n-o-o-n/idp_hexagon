//ldr/elf.h/proc_def_t reimplementation

#include "common.h"
#include "../../ldr/elf/elfbase.h"
#include "../../ldr/elf/elf.h"

proc_def_t::proc_def_t(elf_loader_t &_ldr, reader_t &_reader) : ldr{_ldr}, reader{_reader} {}

bool proc_def_t::proc_supports_relocs() const { return true; }

const char *proc_def_t::proc_handle_reloc(
    const rel_data_t &rel_data,
    const sym_rel *symbol,
    const elf_rela_t *reloc,
    reloc_tools_t *tools) { return 0; }

bool proc_def_t::proc_create_got_offsets(
    const elf_shdr_t *gotps,
    reloc_tools_t *tools) { return false; }

bool proc_def_t::proc_perform_patching(
    const elf_shdr_t *plt,
    const elf_shdr_t *gotps) { return false; }

bool proc_def_t::proc_can_convert_pic_got() const { return false; }

size_t proc_def_t::proc_convert_pic_got(
    const segment_t *gotps,
    reloc_tools_t *tools) { return 0; }

// Return a bit description from e_flags and remove it.
// This function may be called in a loop to document all bits.
const char *proc_def_t::proc_describe_flag_bit(uint32 *e_flags) { return 0; }

// called for processor-specific section types
bool proc_def_t::proc_load_unknown_sec(Elf64_Shdr *sh, bool force) { return force; }

// called for each dynamic tag. It returns NULL to continue with a
// standard tag processing, or "" to finish tag processing, or the
// description of the tag to show.
const char *proc_def_t::proc_handle_dynamic_tag(const Elf64_Dyn *dyn) { return 0; }

bool proc_def_t::proc_is_acceptable_image_type(ushort filetype) { return false; }

// called after header loading (before load_pht/load_simage)
void proc_def_t::proc_on_start_data_loading(elf_ehdr_t &header) {}

// called after loading data from the input file
bool proc_def_t::proc_on_end_data_loading() { return true; }

void proc_def_t::proc_on_loading_symbols() {}

bool proc_def_t::proc_handle_symbol(sym_rel &sym, const char *symname) { return true; }

// Handle a dynamic symbol
void proc_def_t::proc_handle_dynsym(
    const sym_rel &symrel,
    elf_sym_idx_t isym,
    const char *symname) {}

// 0-reaccept, 1-set name only, else: non-existing section
int proc_def_t::proc_handle_special_symbol(
    sym_rel *st,
    const char *name,
    ushort type)
{
    uint16 shndx = st->original.st_shndx;
    int i=NSPEC_SEGMS;
    switch(shndx) 
    { 
        case SHN_UNDEF:
            return -1; 
        case SHN_ABS:
            i = 2;
            break;
        case SHN_COMMON:
            i = 1;
            break;
        default:
            if (shndx<SHN_LORESERVE)
            {
                return -1;;
            }
            for(int j=0; j<NSPEC_SEGMS; j++)
            {
                if (additional_spec_secidx[j]==shndx)
                {
                    i = ((type==6) && (j==0)) ? 3 : j;
                    break;
                }
            }
    }
    if (i>=NSPEC_SEGMS) { return -1; }
    st->original.st_shndx = ldr.spec_segms[i].shn_type;
    return 0;
}

// called from a function should_load_segment for _every_ section.
// It returns 'false' to skip loading of the given section.
bool proc_def_t::proc_should_load_section(
    const elf_shdr_t &sh,
    elf_shndx_t idx,
    const qstring &name) 
{ 
    return ((sh.sh_type==SHT_PROGBITS) || (sh.sh_flags & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_TLS)));
}

// called before the segment creation. It may set <sa> to the ea at
// which a given section should be loaded. In the other case the
// default segment ea computation is used. Also it may return 'false'
// to skip creation of a segment for this section.
bool proc_def_t::proc_on_create_section(
    const elf_shdr_t &sh,
    const qstring &name,
    ea_t *sa) 
{ 
    return true; 
}

const char *proc_def_t::calc_procname(uint32 *e_flags, const char *procname) 
{ 
    return procname; 
}

// for some 64-bit architectures e_entry holds not a real entry point
// but a function descriptor
// E.g. 64-bit PowerPC ELF Application Binary Interface Supplement 1.9
// section 4.1. ELF Header
// "The e_entry field in the ELF header holds the address of a function
// descriptor. This function descriptor supplies both the address of the
// function entry point and the initial value of the TOC pointer
// register."
// this callback should translate this address to the real entry.
ea_t proc_def_t::proc_adjust_entry(ea_t entry)
{
    return entry;
}
