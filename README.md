
## Build

```sh
$ cd submodules/libuv/ && ./autogen.sh && ./configure && make
$ ./build_sh debug
$ ./build_sh sanitizer
$ ./build_sh release
$ ./build_sh release_sanitizer
```

### Build with musl statically with `zig cc`

```sh
$ cd submodules/libuv 
$ cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DLIBUV_BUILD_SHARED=OFF -DCMAKE_C_COMPILER='zig' -D CMAKE_C_COMPILER_ARG1='cc' -DCMAKE_C_FLAGS='--target=x86_64-linux-musl -static'
$ ninja -C build/ libuv.a
$ CC='zig cc' CFLAGS='-static --target=x86_64-linux-musl' ./build.sh release
$ file main.bin
main.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, with debug_info, not stripped
```

## Test

```sh
$ ./test.sh
```

## Run with ASAN

```sh
$ ASAN_OPTIONS="abort_on_error=1:halt_on_error=1:symbolize=0:detect_stack_use_after_return=1" ./main.bin /path/to/file.torrent
```
