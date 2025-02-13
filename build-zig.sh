#!/bin/sh
set -e
set -f # disable globbing.

TARGET=$1
BUILD_DIR="build-$TARGET"

cd submodules/libuv && cmake -G Ninja -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DLIBUV_BUILD_SHARED=OFF -DCMAKE_C_COMPILER=zig -DCMAKE_C_COMPILER_ARG1=cc -DCMAKE_C_FLAGS="--target=$TARGET -static -ffunction-sections -fdata-sections" && ninja -C "$BUILD_DIR" libuv.a && cd ../../

cd submodules/aws-lc && cmake -G Ninja -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DBUILD_LIBSSL=OFF -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DDISABLE_GO=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_COMPILER=zig -DCMAKE_C_COMPILER_ARG1=cc -DCMAKE_C_FLAGS="--target=$TARGET -static -ffunction-sections -fdata-sections -Wno-unknown-warning-option" && ninja -C "$BUILD_DIR" && cd ../..

CC='zig cc' CFLAGS="-static --target=$TARGET -ffunction-sections -fdata-sections" ./build.sh release
