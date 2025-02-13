#pragma once

#include "openssl/sha.h"
#include "submodules/cstd/lib.c"

[[nodiscard]] static PgSha1 sha1_optimized(PgString data) {
  SHA_CTX ctx = {0};
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, data.data, data.len);
  PgSha1 res = {0};
  SHA1_Final(res.data, &ctx);

  return res;
}
