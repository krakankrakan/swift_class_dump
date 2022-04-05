#pragma once

#include <stdint.h>

// __TEXT.__swift5_protos
struct ProtocolDescriptor {
    int32_t Flags;
    int32_t Parent;
    int32_t Name;
    int32_t NumRequirementsInSignature;
    int32_t NumRequirements;
    int32_t AssociatedTypeNames;
} typedef ProtocolDescriptor;

// __TEXT.__swift5_proto
struct ProtocolConformanceDescriptor {
    int32_t ProtocolDescriptor;
    int32_t NominalTypeDescriptor;
    int32_t ProtocolWitnessTable;
    uint32_t ConformanceFlags;
} typedef ProtocolConformanceDescriptor;

// __TEXT.__swift5_types
struct TargetContextDescriptor {
    uint32_t Flags;
    int32_t Parent;
} typedef TargetContextDescriptor;

struct EnumDescriptor {
    uint32_t Flags;
    int32_t Parent;
    int32_t Name;
    int32_t AccessFunction;
    int32_t FieldDescriptor;
    uint32_t NumPayloadCasesAndPayloadSizeOffset;
    uint32_t NumEmptyCases;
} typedef EnumDescriptor;

struct StructDescriptor {
    uint32_t Flags;
    int32_t Parent;
    int32_t Name;
    int32_t AccessFunction;
    int32_t FieldDescriptor;
    uint32_t NumFields;
    uint32_t FieldOffsetVectorOffset;
} typedef StructDescriptor;

struct ClassDescriptor {
    uint32_t Flags;
    int32_t Parent;
    int32_t Name;
    int32_t AccessFunction;
    int32_t FieldDescriptor;
    int32_t SuperclassType;
    uint32_t MetadataNegativeSizeInWords;
    uint32_t MetadataPositiveSizeInWords;
    uint32_t NumImmediateMembers;
    uint32_t NumFields;
    uint32_t FieldOffsetVectorOffset;
    // Optional fields
    uint32_t VTableOffset;
    uint32_t VTableSize;
    // MethodDescriptor[VTableSize]; 
} typedef ClassDescriptor;

struct MethodDescriptor {
    uint32_t Flags;
    int32_t Impl;
} typedef MethodDescriptor;

// __TEXT.__swift5_fieldmd
struct FieldRecord {
    uint32_t Flags;
    int32_t MangledTypeName;
    int32_t FieldName;
} typedef FieldRecord;

struct FieldDescriptor {
    int32_t         MangledTypeName;
    int32_t         Superclass;
    int16_t         Kind;
    int16_t         FieldRecordSize;
    int32_t         NumFields;
    //FieldRecord[]   FieldRecords;     // Array of FieldRecord directly follows this structure
} typedef FieldDescriptor;

// __TEXT.__swift5_assocty
struct AssociatedTypeRecord {
    int32_t Name;
    int32_t SubstitutedTypeName;
} typedef AssociatedTypeRecord;

struct AssociatedTypeDescriptor {
    int32_t ConformingTypeName;
    int32_t ProtocolTypeName;
    uint32_t NumAssociatedTypes;
    uint32_t AssociatedTypeRecordSize;
    //AssociatedTypeRecord[] AssociatedTypeRecords;     // Array of AssociatedTypeRecord directly follows this structure
} typedef AssociatedTypeDescriptor;

// __TEXT.__swift5_builtin
struct BuiltinTypeDescriptor {
    int32_t TypeName;
    uint32_t Size;
    uint32_t AlignmentAndFlags;
    uint32_t Stride;
    uint32_t NumExtraInhabitants;
} typedef BuiltinTypeDescriptor;

enum SwiftType {
    Module          = 0,
    Extension       = 1,
    Anonymous       = 2,
    Protocol        = 3,
    OpaqueType      = 4,
    Type_First      = 16,
    Class           = Type_First,
    Struct          = Type_First + 1,
    Enum            = Type_First + 2,
    Type_Last       = 31,
} typedef SwiftType;

enum MethodKind {
    Method,
    Init,
    Getter,
    Setter,
    ModifyCoroutine,
    ReadCoroutine,
} typedef MethodKind;

#define MethodIsInstanceMask    0x10
#define MethodIsDynamicMask     0x20
#define MethodIsAsyncMask       0x40

void parse_swift_class(void* b, ClassDescriptor *typeDesc);
void parse_swift_struct(StructDescriptor *typeDesc);
void parse_swift_enum(EnumDescriptor *typeDesc);

SwiftType GetSwiftType(uint32_t Flags);
int isGeneric(uint32_t Flags);
int isUnique(uint32_t Flags);
uint8_t getVersion(uint32_t Flags);
uint16_t getKindSpecificFlags(uint32_t Flags);

MethodKind GetMethodKind(uint32_t Flags);
int isDynamic(uint32_t Flags);
int isInstance(uint32_t Flags);
int isAsync(uint32_t Flags);