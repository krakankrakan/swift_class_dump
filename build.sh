#!/bin/bash

clang -Wall src/dump_swift_classes.c src/macho.c src/swift.c -I./include -o dump_swift_classes -g #-fsanitize=address