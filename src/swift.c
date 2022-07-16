#include <class_dump.h>
#include <macho.h>
#include <swift.h>

#include <string.h>

SwiftType GetSwiftType(uint32_t Flags) {
    return (SwiftType)(Flags & 0x1Fu);
}

int isGeneric(uint32_t Flags) {
    return (Flags & 0x80u) != 0;
}

int isUnique(uint32_t Flags) {
    return (Flags & 0x40u) != 0;
}

uint8_t getVersion(uint32_t Flags) {
    return (Flags >> 8u) & 0xFFu; 
}

uint16_t getKindSpecificFlags(uint32_t Flags) {
    return (Flags >> 16u) & 0xFFFFu;
}

MethodKind GetMethodKind(uint32_t Flags) {
    return (MethodKind)(Flags & 0x0F);
}

int isDynamic(uint32_t Flags) {
    return (Flags & MethodIsDynamicMask);
}

int isInstance(uint32_t Flags) { 
    return (Flags & MethodIsInstanceMask);
}

int isAsync(uint32_t Flags) {
    return (Flags & MethodIsAsyncMask);
}

void* get_addr_from_swift_relative_addr(void* base, uint32_t swift_rel_addr) {
    return (void*)((int64_t)base + (int32_t)swift_rel_addr);
}

void parse_swift_field_descriptor(FieldDescriptor *fieldDesc) {
    FieldRecord *currentFieldRecord;

    printf("\tFields:\n");

    //char *class_name = get_addr_from_swift_relative_addr(&fieldDesc->Name, fieldDesc->Name);
    //printf("\t\tName: %s\n", class_name);

    currentFieldRecord = (FieldRecord *)((uint64_t)fieldDesc + sizeof(FieldDescriptor));
    for (unsigned int i = 0; i < fieldDesc->NumFields; i++) {
        char *field_name = get_addr_from_swift_relative_addr(&currentFieldRecord->FieldName, currentFieldRecord->FieldName);
        printf("\t\tFieldName: \t\t%s\n", field_name);

        char *mangled_type_name = get_addr_from_swift_relative_addr(&currentFieldRecord->MangledTypeName, currentFieldRecord->MangledTypeName);
        printf("\t\tMangledTypeName: \t%s\n\n", mangled_type_name);

        currentFieldRecord++;
    }
}

void parse_swift_class(void* b, ClassDescriptor *typeDesc) {
    char *class_name = get_addr_from_swift_relative_addr(&typeDesc->Name, typeDesc->Name);
    printf("\tName: %s\n", class_name);

    if (typeDesc->SuperclassType != 0) {
        ClassDescriptor *superTypeDesc = get_addr_from_swift_relative_addr(&typeDesc->SuperclassType, typeDesc->SuperclassType);
        char *super_class_name = get_addr_from_swift_relative_addr(&superTypeDesc->Name, superTypeDesc->Name);

        //printf("\tSuperclass Name:   %s\n", super_class_name);
    }

    printf("\tFieldDescriptor:   0x%x\n", typeDesc->FieldDescriptor);
    if (typeDesc->FieldDescriptor != 0) {
        FieldDescriptor *fieldDesc = get_addr_from_swift_relative_addr(&typeDesc->FieldDescriptor, typeDesc->FieldDescriptor);
        parse_swift_field_descriptor(fieldDesc);
    }

    printf("\tMethods:\n");
    MethodDescriptor *currentMethodDescriptor = (MethodDescriptor *)((uint64_t)typeDesc + sizeof(ClassDescriptor)); //get_addr_from_swift_relative_addr(&typeDesc->VTableOffset, typeDesc->VTableOffset);
    for (unsigned int i = 0; i < typeDesc->VTableSize; i++) {
        char* MethodName = NULL;
        uint64_t MethodAddr;

        //MethodAddr = (uint64_t)get_addr_from_swift_relative_addr(&currentMethodDescriptor->Impl, currentMethodDescriptor->Impl) - (uint64_t)b;
        
        MethodName = get_symbol_at(b, (int64_t)&currentMethodDescriptor->Impl + (int32_t)currentMethodDescriptor->Impl - (int64_t)b, &MethodAddr);
        
        if (MethodName) {
            printf("\t\tName: %s\n", MethodName);
            
            char *demangled_symbol = demangle_symbol(MethodName);

            if (demangled_symbol != NULL) {
                printf("\t\tDemangled name: %s\n", demangled_symbol);
                free(demangled_symbol);
            }
        }

        if (MethodAddr != 0) {
            printf("\t\tVirtual address: 0x%llx\n", MethodAddr);
        }

        printf("\t\tFlags: 0x%x\t", currentMethodDescriptor->Flags);

        switch(GetMethodKind(currentMethodDescriptor->Flags)) {
            case Method:
                printf("Method");
                break;
            case Init:
                printf("Init");
                break;
            case Getter:
                printf("Getter");
                break;
            case Setter:
                printf("Setter");
                break;
            case ModifyCoroutine:
                printf("ModifyCoroutine");
                break;
            case ReadCoroutine:
                printf("ReadCoroutine");
                break;
        }

        if (isDynamic(currentMethodDescriptor->Flags)) {
            printf(" | Dynamic");
        }
        if (isInstance(currentMethodDescriptor->Flags)) {
            printf(" | Instance");
        }
        if (isAsync(currentMethodDescriptor->Flags)) {
            printf(" | Async");
        }
        printf("\n");

        printf("\t\tImpl:  0x%llx\n", (uint64_t)get_addr_from_swift_relative_addr(&currentMethodDescriptor->Impl, currentMethodDescriptor->Impl) - (uint64_t)b);
        printf("\n");

        currentMethodDescriptor++;
    }
}
 
void parse_swift_struct(StructDescriptor *typeDesc) {
    char *class_name = get_addr_from_swift_relative_addr(&typeDesc->Name, typeDesc->Name);
    printf("\tName: %s\n", class_name);

    printf("\tFieldDescriptor:   0x%x\n", typeDesc->FieldDescriptor);
    if (typeDesc->FieldDescriptor != 0) {
        FieldDescriptor *fieldDesc = get_addr_from_swift_relative_addr(&typeDesc->FieldDescriptor, typeDesc->FieldDescriptor);
        parse_swift_field_descriptor(fieldDesc);
    }
}

void parse_swift_enum(EnumDescriptor *typeDesc) {
    char *class_name = get_addr_from_swift_relative_addr(&typeDesc->Name, typeDesc->Name);
    printf("\tName: %s\n", class_name);

    printf("\tFieldDescriptor:   0x%x\n", typeDesc->FieldDescriptor);
    if (typeDesc->FieldDescriptor != 0) {
        FieldDescriptor *fieldDesc = get_addr_from_swift_relative_addr(&typeDesc->FieldDescriptor, typeDesc->FieldDescriptor);
        parse_swift_field_descriptor(fieldDesc);
    }
}

void insertString(char* dst, int pos, char* insert, size_t max_size)
{
    char *dst_new;

    if (pos >= max_size) {
        return;
    }

    dst_new = (char*) malloc(strlen(dst) + strlen(insert) + 1);
    strncpy(dst_new, dst, pos);
    dst_new[pos] = '\0';
    strncat(dst_new, insert, max_size);
    strncat(dst_new, dst + pos, max_size);
    strncpy(dst, dst_new, max_size);
    free(dst_new);
}

char* demangle_symbol(char* symbol) {
    FILE *fp;
    char *buf = malloc(1024);
    char *demangled_symbol = malloc(1024);
    char *escaped_symbol = malloc(1024);
    strncpy(escaped_symbol, symbol, 1024);

    for (unsigned int i = 1; i < strlen(escaped_symbol); i++) {
        if (escaped_symbol[i] == '$') {
            insertString(escaped_symbol, i, "\\", 1024);
            i++;
        }
    }

    char* cmd = (char*)malloc(2048);
    strncpy(cmd, "swift demangle -compact -simplified ", 2048);
    cmd = strcat(cmd, escaped_symbol);

    //printf("Running cmd: %s\n", cmd);

    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }

    memset(demangled_symbol, 0, 1024);

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        strncat(demangled_symbol, buf, 1024);
    }

    pclose(fp);

    if (strcmp(demangled_symbol, "_\n") == 0) {
        return NULL;
    }

    if (demangled_symbol[strlen(demangled_symbol) - 1] == '\n') {
        demangled_symbol[strlen(demangled_symbol) - 1] = 0;
    }

    //printf("%s", demangled_symbol);

    return demangled_symbol;
}