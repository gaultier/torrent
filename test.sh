#!/bin/sh
set -e
set -f # disable globbing.

CFLAGS="${CFLAGS} -fpie -flto -fno-omit-frame-pointer -gsplit-dwarf -march=native -fuse-ld=lld -I./submodules/libuv/include"
LDFLAGS="${LDFLAGS} -L./submodules/libuv/build/ -luv -Wl,--gc-sections"
CC="${CC:-clang}"
WARNINGS="$(tr -s '\n' ' ' < compile_flags.txt)"

# shellcheck disable=SC2086
$CC -O0 $WARNINGS -g3 test.c -o test.bin -fsanitize=address,undefined -fsanitize-trap=all $CFLAGS $LDFLAGS && ASAN_OPTIONS='detect_leaks=0' ./test.bin
