
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
$ cd submodules/libuv && ./autogen.sh && CC='zig cc' CFLAGS='-fPIC --target=x86_64-linux-musl' ./configure && make
$ CC='zig cc' CFLAGS='-static --target=x86_64-linux-musl' ./build.sh release
$ file main.bin
main.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, with debug_info, not stripped
```

## Test

```sh
$ ./test.sh
```
