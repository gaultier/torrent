#!/bin/sh
set -e
set -f # disable globbing.

TARGET=$1
BUILD_DIR="build-$TARGET"

cd submodules/libuv && cmake -G Ninja -S . -B "$BUILD_DIR" -DCMAKE_INSTALL_MESSAGE=NEVER -DCMAKE_MESSAGE_LOG_LEVEL="ERROR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DLIBUV_BUILD_SHARED=OFF -DCMAKE_C_COMPILER=zig-cc -DCMAKE_C_FLAGS="--target=$TARGET -static -ffunction-sections -fdata-sections" && ninja -C "$BUILD_DIR" libuv.a && cd ../../

CC='zig cc' CFLAGS="$CFLAGS --target=$TARGET -ffunction-sections -fdata-sections -Wno-unused-command-line-argument" LDFLAGS="$LDFLAGS -static -L./submodules/libuv/$BUILD_DIR" sh -x ./build.sh release
