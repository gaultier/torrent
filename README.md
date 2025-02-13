
## Build

*Requirements: cmake, ninja, (perl?).*

```sh
$ ./build_sh debug
$ ./build_sh debug_sanitizer
$ ./build_sh release
$ ./build_sh release_sanitizer
```

### Build with musl statically with `zig cc`

```sh
$ ./build-zig.sh x86_64-linux-musl
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
