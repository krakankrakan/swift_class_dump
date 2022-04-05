#pragma once

#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

void parse_mach_header(void* b, size_t current_offset);
int parse_fat_header(void* b, uint64_t* base);
char* get_symbol_at(void* b, uint64_t file_offset, uint64_t *ret_vaddr);