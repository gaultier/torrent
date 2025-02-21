#pragma once

#include "submodules/cstd/lib.c"
#include "uv.h"

[[nodiscard]] [[maybe_unused]]
static PgString uv_buf_to_string(uv_buf_t buf) {
  return (PgString){.data = (u8 *)buf.base, .len = (u64)buf.len};
}

[[nodiscard]]
static uv_buf_t string_to_uv_buf(PgString s) {
  uv_buf_t res = {0};
  res.base = (char *)s.data;
  res.len = (typeof(res.len))s.len;

  return res;
}

PG_SLICE(uv_fs_t) UvFsSlice;
PG_SLICE(uv_buf_t) UvBufSlice;
