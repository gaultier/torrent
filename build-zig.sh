#!/bin/sh
set -e
set -f # disable globbing.

TARGET=$1
BUILD_DIR="build-$TARGET"

cd submodules/libuv && cmake -G Ninja -S . -B "$BUILD_DIR" -DCMAKE_INSTALL_MESSAGE=NEVER -DCMAKE_MESSAGE_LOG_LEVEL="ERROR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DLIBUV_BUILD_SHARED=OFF -DCMAKE_C_COMPILER=zig-cc -DCMAKE_C_FLAGS="--target=$TARGET -static -ffunction-sections -fdata-sections" && ninja -C "$BUILD_DIR" libuv.a && cd ../../

cd submodules/aws-lc && cmake -G Ninja -S . -B "$BUILD_DIR" -DCMAKE_INSTALL_MESSAGE=NEVER -DCMAKE_MESSAGE_LOG_LEVEL="ERROR" -DCMAKE_BUILD_TYPE=Release -DBUILD_LIBSSL=OFF -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DDISABLE_GO=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_COMPILER=zig-cc -DCMAKE_C_FLAGS="--target=$TARGET -static -ffunction-sections -fdata-sections -Wno-unknown-warning-option" && ninja -C "$BUILD_DIR" && cd ../..

CC='zig cc' CFLAGS="--target=$TARGET -ffunction-sections -fdata-sections -Wno-unused-command-line-argument" LDFLAGS="-static -L./submodules/libuv/$BUILD_DIR -L./submodules/aws-lc/$BUILD_DIR/crypto" ./build.sh release
