#!/bin/sh
set -e
set -f # disable globbing.

CFLAGS="${CFLAGS}"
EXTRA_FLAGS="-fpie -L./submodules/libuv/build/ -luv -flto -fno-omit-frame-pointer -gsplit-dwarf -march=native"
CC="${CC:-clang}"
WARNINGS="$(tr -s '\n' ' ' < compile_flags.txt)"

error() {
	printf "ERROR: %s\n" "$1"
	exit 1
}

build() {
case $1 in 
  debug)
    EXTRA_FLAGS="${EXTRA_FLAGS} -O0"
    ;;
  sanitizer)
    EXTRA_FLAGS="${EXTRA_FLAGS} -O0 -fsanitize=address,undefined -fsanitize-trap=all"
    ;;
  release)
    EXTRA_FLAGS="${EXTRA_FLAGS} -O3 -Wl,--gc-sections"
    ;;
  release_sanitizer)
    EXTRA_FLAGS="${EXTRA_FLAGS} -O1 -fsanitize=address,undefined -fsanitize-trap=all -Wl,--gc-sections"
    ;;
	*)
		error "Build mode \"$1\" unsupported!"
		;;
esac

# shellcheck disable=SC2086
$CC $WARNINGS -g3 main.c -o main.bin $EXTRA_FLAGS $CFLAGS
}

if [ $# -eq 0 ]; then
	build debug
elif [ $# -eq 1 ]; then
  build "$1"
else
	error "Too many arguments!"
fi
