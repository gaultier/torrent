#!/bin/sh
set -e
set -f # disable globbing.

CC="${CC:-clang}"
WARNINGS="$(tr -s '\n' ' ' < compile_flags.txt)"

# shellcheck disable=SC2086
"$CC" -O0 $WARNINGS -g3 test.c -o test.bin -fsanitize=address,undefined -fsanitize-trap=all && ASAN_OPTIONS='detect_leaks=0' ./test.bin
