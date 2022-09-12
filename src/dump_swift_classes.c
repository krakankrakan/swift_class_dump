#include <class_dump.h>
#include <macho.h>
#include <swift.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct section_64   *__swift5_protos_section  = NULL;
struct section_64   *__swift5_proto_section   = NULL;
struct section_64   *__swift5_types_section   = NULL;
struct section_64   *__swift5_fieldmd_section = NULL;
struct section_64   *__swift5_assocty_section = NULL;
struct section_64   *__swift5_builtin_section = NULL;


int main(int argc, char** argv) {
    FILE                    *f;
    void                    *file_content;
    void                    *new_base;

    if (argc < 2) {
        printf("Missing file!\n");
        return EXIT_FAILURE;
    }

    f = fopen(argv[1], "r");
    if (f == NULL) {
        printf("Could not open file!\n");
        return EXIT_FAILURE;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    file_content = malloc(fsize + 1);

    fread(file_content, fsize, 1, f);
    fclose(f);

    int ret = parse_fat_header(file_content, (uint64_t*)&new_base);
    if (ret != 0) {
        DEBUG_PRINTF("Fat header not found, trying parsing Mach-O header instead...\n");
        new_base = file_content;
        parse_mach_header(file_content, 0);
    }

    if (!__swift5_protos_section  ||
        !__swift5_proto_section   || 
        !__swift5_types_section   || 
        !__swift5_fieldmd_section || 
        !__swift5_assocty_section || 
        !__swift5_builtin_section) {
        DEBUG_PRINTF("Could not find all Swift sections!\n");
    }

    if (!__swift5_types_section) {
        printf("Could not find Swift type section!\n");
        return EXIT_FAILURE;
    }

    DEBUG_PRINTF("new_base: 0x%llx\n", (uint64_t)new_base);
    DEBUG_PRINTF("__swift5_types_section: 0x%llx\n", (uint64_t)__swift5_types_section);

    for (unsigned int i = 0; i < (__swift5_types_section->size / sizeof(uint32_t)); i++) {
        DEBUG_PRINTF("__swift5_types_section->offset: 0x%llx\n", (uint64_t)__swift5_types_section->offset);

        uint64_t section_data = (uint64_t)new_base + __swift5_types_section->offset;
        uint32_t *type_ptr = &((uint32_t*)section_data)[i];

        DEBUG_PRINTF("type_ptr: 0x%llx\n", (int64_t)type_ptr);
        DEBUG_PRINTF("*type_ptr: 0x%x\n", (int32_t)*type_ptr);

        TargetContextDescriptor *typeDesc = (TargetContextDescriptor*)((int64_t)type_ptr + (int32_t)*type_ptr); //(uint32_t*) (section_data + i * sizeof(uint32_t) + ((uint32_t*)section_data)[i]);

        DEBUG_PRINTF("nominalTypeDesc: 0x%llx\n", (uint64_t)typeDesc);
        //DEBUG_PRINTF("%x\n%x\n", typeDesc->Flags, typeDesc->Parent);
        //DEBUG_PRINTF("0x%x\n", GetSwiftType(typeDesc->Flags));

        if (!((uint64_t)typeDesc >= (uint64_t)new_base && (uint64_t)typeDesc <= (uint64_t)new_base + fsize)) {
            printf("Could not parse type descriptor\n");
            continue;
        }

        switch (GetSwiftType(typeDesc->Flags)) {
            case Class:
                printf("Class\n");
                parse_swift_class(new_base, (ClassDescriptor *)typeDesc);
                break;
            case Struct:
                printf("Struct\n");
                parse_swift_struct((StructDescriptor *)typeDesc);
                break;
            case Enum:
                printf("Enum\n");
                parse_swift_enum((EnumDescriptor *)typeDesc);
                break;
            default:
                printf("Could not recognize swift type: 0x%x!\n", GetSwiftType(typeDesc->Flags));
                break;
        }
    }

    free(file_content);

    return EXIT_SUCCESS;
}