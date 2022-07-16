#pragma once

#include <stdio.h>
#include <mach-o/loader.h>

#define DEBUG   1
#define DEBUG_PRINTF(fmt, ...) \
            do { if (DEBUG) printf(fmt, ##__VA_ARGS__); } while (0)

extern struct section_64   *__swift5_protos_section;
extern struct section_64   *__swift5_proto_section;
extern struct section_64   *__swift5_types_section;
extern struct section_64   *__swift5_fieldmd_section;
extern struct section_64   *__swift5_assocty_section;
extern struct section_64   *__swift5_builtin_section;