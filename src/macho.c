#include <class_dump.h>
#include <macho.h>

#include <string.h>

int check_fat_byteswap(uint32_t magic) {
    if (magic == FAT_CIGAM_64 || magic == FAT_CIGAM) return 1;
    if (magic == FAT_MAGIC_64 || magic == FAT_MAGIC) return 0;
    return 0;
}

int check_macho_byteswap(uint32_t magic) {
    if (magic == MH_CIGAM_64 || magic == MH_CIGAM) return 1;
    if (magic == MH_MAGIC_64 || magic == MH_MAGIC) return 0;
    return 0;
}

int check_fat_magic_valid(uint32_t magic) {
        if (magic == FAT_CIGAM_64 || magic == FAT_CIGAM) return 1;
        if (magic == FAT_MAGIC_64 || magic == FAT_MAGIC) return 1;
        return 0;
}

int check_macho_magic_valid(uint32_t magic) {
        if (magic == MH_CIGAM_64 || magic == MH_CIGAM) return 1;
        if (magic == MH_MAGIC_64 || magic == MH_MAGIC) return 1;
        return 0;
}

int check_is_fat_64(uint32_t magic) {
    if (magic == FAT_MAGIC_64) return 1;
    return 0;
}

int check_is_macho_64(uint32_t magic) {
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) return 1;
    return 0;
}

void swap_f_hdr(struct fat_header *f_hdr) {
    f_hdr->magic        = __builtin_bswap32(f_hdr->magic);
    f_hdr->nfat_arch    = __builtin_bswap32(f_hdr->nfat_arch);
}

void swap_f_arch_64(struct fat_arch_64 *f_arch_64) {
    f_arch_64->cputype      = __builtin_bswap32(f_arch_64->cputype);
    f_arch_64->cpusubtype   = __builtin_bswap32(f_arch_64->cpusubtype);
    f_arch_64->offset       = __builtin_bswap64(f_arch_64->offset);
    f_arch_64->size         = __builtin_bswap64(f_arch_64->size);
    f_arch_64->align        = __builtin_bswap32(f_arch_64->align);
    f_arch_64->reserved     = __builtin_bswap32(f_arch_64->reserved);
}

void swap_f_arch(struct fat_arch *f_arch) {
    f_arch->cputype      = __builtin_bswap32(f_arch->cputype);
    f_arch->cpusubtype   = __builtin_bswap32(f_arch->cpusubtype);
    f_arch->offset       = __builtin_bswap32(f_arch->offset);
    f_arch->size         = __builtin_bswap32(f_arch->size);
    f_arch->align        = __builtin_bswap32(f_arch->align);
}

void swap_m_hdr_64(struct mach_header_64 *m_hdr_64) {
    m_hdr_64->magic         = __builtin_bswap32(m_hdr_64->magic);
    m_hdr_64->cputype       = __builtin_bswap32(m_hdr_64->cputype);
    m_hdr_64->cpusubtype    = __builtin_bswap32(m_hdr_64->cpusubtype);
    m_hdr_64->filetype      = __builtin_bswap32(m_hdr_64->filetype);
    m_hdr_64->ncmds         = __builtin_bswap32(m_hdr_64->ncmds);
    m_hdr_64->sizeofcmds    = __builtin_bswap32(m_hdr_64->sizeofcmds);
    m_hdr_64->flags         = __builtin_bswap32(m_hdr_64->flags);
    m_hdr_64->reserved      = __builtin_bswap32(m_hdr_64->reserved);
}

char* filetype_string(uint32_t filetype) {
    char* ret;

    switch (filetype) {
        case MH_OBJECT:
            ret = "MH_OBJECT";
            break;
        case MH_EXECUTE:
            ret = "MH_EXECUTE";
            break;
        case MH_FVMLIB:
            ret = "MH_FVMLIB";
            break;
        case MH_CORE:
            ret = "MH_CORE";
            break;
        case MH_PRELOAD:
            ret = "MH_PRELOAD";
            break;
        case MH_DYLIB:
            ret = "MH_DYLIB";
            break;
        case MH_DYLINKER:
            ret = "MH_DYLINKER";
            break;
        case MH_BUNDLE:
            ret = "MH_BUNDLE";
            break;
        case MH_DYLIB_STUB:
            ret = "MH_DYLIB_STUB";
            break;
        case MH_DSYM:
            ret = "MH_DSYM";
            break;
        case MH_KEXT_BUNDLE:
            ret = "MH_KEXT_BUNDLE";
            break;
        case MH_FILESET:
            ret = "MH_FILESET";
            break;
        default:
            ret = "UNKNOWN";
            break;
    }

    return ret;
}

char* cmd_string(uint32_t cmd) {
    char* ret;

    switch (cmd) {
        case LC_SEGMENT:
            ret = "LC_SEGMENT";
            break;
        case LC_SYMTAB:
            ret = "LC_SYMTAB";
            break;
        case LC_SYMSEG:
            ret = "LC_SYMSEG";
            break;
        case LC_THREAD:
            ret = "LC_THREAD";
            break;
        case LC_UNIXTHREAD:
            ret = "LC_UNIXTHREAD";
            break;
        case LC_LOADFVMLIB:
            ret = "LC_LOADFVMLIB";
            break;
        case LC_IDFVMLIB:
            ret = "LC_IDFVMLIB";
            break;
        case LC_IDENT:
            ret = "LC_IDENT";
            break;
        case LC_FVMFILE:
            ret = "LC_FVMFILE";
            break;
        case LC_PREPAGE:
            ret = "LC_PREPAGE";
            break;
        case LC_DYSYMTAB:
            ret = "LC_DYSYMTAB";
            break;
        case LC_LOAD_DYLIB:
            ret = "LC_LOAD_DYLIB";
            break;
        case LC_ID_DYLIB:
            ret = "LC_ID_DYLIB";
            break;
        case LC_LOAD_DYLINKER:
            ret = "LC_LOAD_DYLINKER";
            break;
        case LC_ID_DYLINKER:
            ret = "LC_ID_DYLINKER";
            break;
        case LC_PREBOUND_DYLIB:
            ret = "LC_PREBOUND_DYLIB";
            break;
        case LC_ROUTINES:
            ret = "LC_ROUTINES";
            break;
        case LC_SUB_FRAMEWORK:
            ret = "LC_SUB_FRAMEWORK";
            break;
        case LC_SUB_UMBRELLA:
            ret = "LC_SUB_UMBRELLA";
            break;
        case LC_SUB_CLIENT:
            ret = "LC_SUB_CLIENT";
            break;
        case LC_SUB_LIBRARY:
            ret = "LC_SUB_LIBRARY";
            break;
        case LC_TWOLEVEL_HINTS:
            ret = "LC_TWOLEVEL_HINTS";
            break;
        case LC_PREBIND_CKSUM:
            ret = "LC_PREBIND_CKSUM";
            break;
        case LC_LOAD_WEAK_DYLIB:
            ret = "LC_LOAD_WEAK_DYLIB";
            break;
        case LC_SEGMENT_64:
            ret = "LC_SEGMENT_64";
            break;
        case LC_ROUTINES_64:
            ret = "LC_ROUTINES_64";
            break;
        case LC_UUID:
            ret = "LC_UUID";
            break;
        case LC_RPATH:
            ret = "LC_RPATH";
            break;
        case LC_CODE_SIGNATURE:
            ret = "LC_CODE_SIGNATURE";
            break;
        case LC_SEGMENT_SPLIT_INFO:
            ret = "LC_SEGMENT_SPLIT_INFO";
            break;
        case LC_REEXPORT_DYLIB:
            ret = "LC_REEXPORT_DYLIB";
            break;
        case LC_LAZY_LOAD_DYLIB:
            ret = "LC_LAZY_LOAD_DYLIB";
            break;
        case LC_ENCRYPTION_INFO:
            ret = "LC_ENCRYPTION_INFO";
            break;
        case LC_DYLD_INFO:
            ret = "LC_DYLD_INFO";
            break;
        case LC_DYLD_INFO_ONLY:
            ret = "LC_DYLD_INFO_ONLY";
            break;
        case LC_LOAD_UPWARD_DYLIB:
            ret = "LC_LOAD_UPWARD_DYLIB";
            break;
        case LC_VERSION_MIN_MACOSX:
            ret = "LC_VERSION_MIN_MACOSX";
            break;
        case LC_VERSION_MIN_IPHONEOS:
            ret = "LC_VERSION_MIN_IPHONEOS";
            break;
        case LC_FUNCTION_STARTS:
            ret = "LC_FUNCTION_STARTS";
            break;
        case LC_DYLD_ENVIRONMENT:
            ret = "LC_DYLD_ENVIRONMENT";
            break;
        case LC_MAIN:
            ret = "LC_MAIN";
            break;
        case LC_DATA_IN_CODE:
            ret = "LC_DATA_IN_CODE";
            break;
        case LC_SOURCE_VERSION:
            ret = "LC_SOURCE_VERSION";
            break;
        case LC_DYLIB_CODE_SIGN_DRS:
            ret = "LC_DYLIB_CODE_SIGN_DRS";
            break;
        case LC_ENCRYPTION_INFO_64:
            ret = "LC_ENCRYPTION_INFO_64";
            break;
        case LC_LINKER_OPTION:
            ret = "LC_LINKER_OPTION";
            break;
        case LC_LINKER_OPTIMIZATION_HINT:
            ret = "LC_LINKER_OPTIMIZATION_HINT";
            break;
        case LC_VERSION_MIN_TVOS:
            ret = "LC_VERSION_MIN_TVOS";
            break;
        case LC_VERSION_MIN_WATCHOS:
            ret = "LC_VERSION_MIN_WATCHOS";
            break;
        case LC_NOTE:
            ret = "LC_NOTE";
            break;
        case LC_BUILD_VERSION:
            ret = "LC_BUILD_VERSION";
            break;
        case LC_DYLD_EXPORTS_TRIE:
            ret = "LC_DYLD_EXPORTS_TRIE";
            break;
        case LC_DYLD_CHAINED_FIXUPS:
            ret = "LC_DYLD_CHAINED_FIXUPS";
            break;
        case LC_FILESET_ENTRY:
            ret = "LC_FILESET_ENTRY";
            break;
        default:
            ret = "UNKNOWN";
            break;
    }

    return ret;
}

char* prot_string(uint32_t prot) {
    char ret[4];

    ret[0] = '-';
    ret[1] = '-';
    ret[2] = '-';

    if ((prot & VM_PROT_READ) == VM_PROT_READ) {
        ret[0] = 'R';
    }

    if ((prot & VM_PROT_WRITE) == VM_PROT_WRITE) {
        ret[1] = 'W';
    }

    if ((prot & VM_PROT_EXECUTE) == VM_PROT_EXECUTE) {
        ret[2] = 'X';
    }

    ret[3] = 0;

    return strdup(ret);
}

void parse_sections(void* b, size_t current_offset, unsigned int nsects, int is_64) {
    struct section_64   section_64;

    if (nsects > 0) {
        DEBUG_PRINTF("\t\tSections:\n");
    } else {
        return;
    }

    for (unsigned int i = 0; i < nsects; i++) {
        if (is_64) {
            memcpy(&section_64, (void*)((uint64_t)b + current_offset), sizeof(struct section_64));

            DEBUG_PRINTF("\t\t\t%s:\n",              section_64.sectname);
            DEBUG_PRINTF("\t\t\t\taddr:   0x%llx\n", section_64.addr);
            DEBUG_PRINTF("\t\t\t\tsize:   0x%llx\n", section_64.size);
            DEBUG_PRINTF("\t\t\t\toffset: 0x%x\n",   section_64.offset);
            DEBUG_PRINTF("\t\t\t\talign:  0x%x\n",   section_64.align);
            DEBUG_PRINTF("\t\t\t\treloff: 0x%x\n",   section_64.reloff);
            DEBUG_PRINTF("\t\t\t\tnreloc: 0x%x\n",   section_64.nreloc);
            DEBUG_PRINTF("\t\t\t\tflags:  0x%x\n",   section_64.flags);

            if (strcmp(section_64.sectname, "__swift5_protos") == 0) {
                __swift5_protos_section = (struct section_64*)((uint64_t)b + current_offset);
            }
            if (strcmp(section_64.sectname, "__swift5_proto") == 0) {
                __swift5_proto_section = (struct section_64*)((uint64_t)b + current_offset);
            }
            if (strcmp(section_64.sectname, "__swift5_types") == 0) {
                __swift5_types_section = (struct section_64*)((uint64_t)b + current_offset);
            }
            if (strcmp(section_64.sectname, "__swift5_fieldmd") == 0) {
                __swift5_fieldmd_section = (struct section_64*)((uint64_t)b + current_offset);
            }
            if (strcmp(section_64.sectname, "__swift5_assocty") == 0) {
                __swift5_assocty_section = (struct section_64*)((uint64_t)b + current_offset);
            }
            if (strcmp(section_64.sectname, "__swift5_builtin") == 0) {
                __swift5_builtin_section = (struct section_64*)((uint64_t)b + current_offset);
            }
        } else {
            DEBUG_PRINTF("32 bit not supported!\n");
            exit(1);
        }
        current_offset += sizeof(struct section_64);
    }
}

void parse_cmds(void* b, size_t current_offset, unsigned int ncmds, void *m, int is_64, int should_swap) {
    for (unsigned int i = 0; i < ncmds; i++) {
        struct load_command l_cmd;

        memcpy(&l_cmd, (void*)((uint64_t)b + current_offset), sizeof(struct load_command));

        DEBUG_PRINTF("\tcmd: 0x%x, %s\n", l_cmd.cmd, cmd_string(l_cmd.cmd));
        DEBUG_PRINTF("\t\tsize: 0x%x\n", l_cmd.cmdsize);

        if (l_cmd.cmd == LC_SEGMENT_64) {
            struct segment_command_64   segment;
            char                        *prot_str;

            memcpy(&segment, (void*)((uint64_t)b + current_offset), sizeof(struct segment_command_64));

            DEBUG_PRINTF("\t\t%s\n", segment.segname);
            DEBUG_PRINTF("\t\tvmaddr:   0x%llx\n", segment.vmaddr);
            DEBUG_PRINTF("\t\tvmsize:   0x%llx\n", segment.vmsize);
            DEBUG_PRINTF("\t\tfileoff:  0x%llx\n", segment.fileoff);
            DEBUG_PRINTF("\t\tfilesize: 0x%llx\n", segment.filesize);

            prot_str = prot_string(segment.maxprot);
            DEBUG_PRINTF("\t\tmaxprot:  0x%x, %s\n", segment.maxprot, prot_str);
            free(prot_str);

            prot_str = prot_string(segment.initprot);
            DEBUG_PRINTF("\t\tinitprot: 0x%x, %s\n", segment.initprot, prot_str);
            free(prot_str);

            DEBUG_PRINTF("\t\tnsects:   0x%x\n", segment.nsects);
            DEBUG_PRINTF("\t\tflags:    0x%x\n", segment.flags);

            parse_sections(b, current_offset + sizeof(struct segment_command_64), segment.nsects, 1);
        }

        current_offset += l_cmd.cmdsize;
    }
}

void parse_mach_header(void* b, size_t current_offset) {
    struct mach_header_64   m_hdr_64;
    int                     should_swap = 0;

    memcpy(&m_hdr_64, (void*)((uint64_t)b + current_offset), sizeof(struct mach_header_64));
    current_offset += sizeof(struct mach_header_64);

    if (!check_macho_magic_valid(m_hdr_64.magic)) {
        printf("Mach-O magic is not valid! Got: 0x%x\n", m_hdr_64.magic);
        exit(1);
    }

    if (!check_is_macho_64(m_hdr_64.magic)) {
        printf("Mach-O magic is not a 64-bit Mach-O!\n");
        exit(1);
    }

    if (check_macho_byteswap(m_hdr_64.magic)) {
        swap_m_hdr_64(&m_hdr_64);
        should_swap = 1;
    }

    DEBUG_PRINTF("\tcputype: 0x%x\n", m_hdr_64.cputype);
    DEBUG_PRINTF("\tcpusubtype: 0x%x\n", m_hdr_64.cpusubtype);
    DEBUG_PRINTF("\tfiletype: 0x%x, %s\n", m_hdr_64.filetype, filetype_string(m_hdr_64.filetype));
    DEBUG_PRINTF("\tncmds: 0x%x\n", m_hdr_64.ncmds);
    DEBUG_PRINTF("\tsizeofcmds: 0x%x\n", m_hdr_64.sizeofcmds);
    DEBUG_PRINTF("\tflags: 0x%x\n", m_hdr_64.flags);

    parse_cmds(b, current_offset, m_hdr_64.ncmds, &m_hdr_64, 1, should_swap);
}

int parse_fat_header(void* b, uint64_t* base) {
    struct fat_header       f_hdr;
    size_t                  m_hdr_total_count = 0;
    int                     should_swap = 0;
    int                     is_64 = 0;
    uint32_t                target_arch = 0;
    int                     found_target_arch = 0;

    // Current position we are parsing from.
    size_t                  current_offset = 0;

    memcpy(&f_hdr, b, sizeof(struct fat_header));

    if (!check_fat_magic_valid(f_hdr.magic)) {
        return 1;
    }

    if (check_fat_byteswap(f_hdr.magic)) {
        swap_f_hdr(&f_hdr);
        should_swap = 1;
    }

    if (check_is_fat_64(f_hdr.magic)) {
        DEBUG_PRINTF("Fat magic is a 64-bit Fat!\n");
        is_64 = 1;
    } else {
        DEBUG_PRINTF("Fat magic is not a 64-bit Fat: 0x%x!\n", f_hdr.magic);
    }

    current_offset += sizeof(struct fat_header);

    char* target_arch_str = getenv("ARCH");
    if (target_arch_str == NULL) {
        printf("Executable has multiple architectures, but none have been selected via ARCH env var!\n");
        exit(1);
    }
    
    if (strcmp(target_arch_str, "ARM") == 0) {
        target_arch = CPU_TYPE_ARM64;
    } else if (strcmp(target_arch_str, "x64") == 0) {
        target_arch = CPU_TYPE_X86_64;
    } else {
        printf("Passed architecture not supported!\n");
        exit(1);
    }

    printf("Selected architecture: 0x%x\n", target_arch);

    for (unsigned int i = 0; i < f_hdr.nfat_arch; i++) {
        struct fat_arch_64      f_arch_64;
        struct fat_arch         f_arch;

        if (is_64) {
            memcpy(&f_arch_64, (void*)((uint64_t)b + current_offset), sizeof(struct fat_arch_64));
            current_offset += sizeof(struct fat_arch_64);

            if (should_swap) {
                swap_f_arch_64(&f_arch_64);
            }

            if (f_arch_64.cputype == target_arch) {
                found_target_arch = 1;
                current_offset = f_arch_64.offset;
                break;
            }
        } else {
            memcpy(&f_arch, (void*)((uint64_t)b + current_offset), sizeof(struct fat_arch));
            current_offset += sizeof(struct fat_arch);

            if (should_swap) {
                swap_f_arch(&f_arch);
            }

            if (f_arch.cputype == target_arch) {
                found_target_arch = 1;
                current_offset = f_arch.offset;
                break;
            }
        }
    }

    if (!found_target_arch) {
        printf("Could not find target architecture!\n");
        exit(1);
    }

    if (check_fat_magic_valid(f_hdr.magic)) {
    } else {
        // Maybe there is no fat header? Read in the single Mach-O header
        m_hdr_total_count = 1;
    }

    DEBUG_PRINTF("Parsing Mach-O headers!\n");
    DEBUG_PRINTF("Fat header: 0x%llx\n", (uint64_t)b);
    DEBUG_PRINTF("Mach-O header: 0x%llx\n", (uint64_t)((uint64_t)b + current_offset));
    parse_mach_header((void*)((uint64_t)b + current_offset), 0);

    *base = (uint64_t)((uint64_t)b + current_offset);

    return 0;
}

uint64_t map_file_offset_to_vaddr(uint64_t offset) {
    return 0;
}

char* get_symbol_at(void* b, uint64_t file_offset) {
    uint64_t vaddr;

    vaddr = map_file_offset_to_vaddr(file_offset);

    return NULL;
}