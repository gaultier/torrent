#pragma once

#include "submodules/cstd/lib.c"
#include "uv.h"

[[nodiscard]] __attribute((unused))
static PgString uv_buf_to_string(uv_buf_t buf) {
  return (PgString){.data = (u8 *)buf.base, .len = buf.len};
}

[[nodiscard]]
static uv_buf_t string_to_uv_buf(PgString s) {
  return (uv_buf_t){.base = (char *)s.data, .len = s.len};
}
