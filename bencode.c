#pragma once

#include "submodules/cstd/lib.c"

#include "configuration.c"
#include "uv_utils.c"

typedef enum {
  BENCODE_KIND_NONE,
  BENCODE_KIND_NUMBER,
  BENCODE_KIND_STRING,
  BENCODE_KIND_LIST,
  BENCODE_KIND_DICTIONARY,
} BencodeKind;

typedef struct BencodeValue BencodeValue;

PG_DYN(BencodeValue) BencodeValueDyn;

typedef struct BencodeKeyValue BencodeKeyValue;
PG_DYN(BencodeKeyValue) BencodeKeyValueDyn;

// TODO: Optimize size?
struct BencodeValue {
  BencodeKind kind;
  u32 start, end;
  union {
    u64 num;
    PgString s; // Non-owning.
    BencodeValueDyn list;
    BencodeKeyValueDyn dict;
  };
};

struct BencodeKeyValue {
  PgString key;
  BencodeValue value;
};

typedef struct {
  PgError err;
  BencodeValue value;
  PgString remaining; // Non-owning.
} BencodeValueDecodeResult;

__attribute((warn_unused_result)) static BencodeValueDecodeResult
bencode_decode_value(PgString s, u32 start, PgAllocator *allocator);

__attribute((warn_unused_result)) static BencodeValueDecodeResult bencode_decode_number(PgString s,
                                                                    u32 start) {
  BencodeValueDecodeResult res = {
      .value.start = start,
      .value.kind = BENCODE_KIND_NUMBER,
  };

  PgStringOk prefix = pg_string_consume_byte(s, 'i');
  if (!prefix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  PgParseNumberResult num_res = pg_string_parse_u64(prefix.res);
  if (!num_res.present) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  res.value.num = num_res.n;

  PgStringOk suffix = pg_string_consume_byte(num_res.remaining, 'e');
  if (!suffix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }
  res.remaining = suffix.res;
  res.value.end = (u32)(start + s.len - res.remaining.len);
  return res;
}

__attribute((warn_unused_result)) static BencodeValueDecodeResult bencode_decode_string(PgString s,
                                                                    u32 start) {
  BencodeValueDecodeResult res = {
      .value.start = start,
      .value.kind = BENCODE_KIND_STRING,
  };

  PgParseNumberResult num_res = pg_string_parse_u64(s);
  if (!num_res.present) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  if (0 == num_res.n) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  PgStringOk prefix = pg_string_consume_byte(num_res.remaining, ':');
  if (!prefix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  if (prefix.res.len < num_res.n) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  res.value.s = PG_SLICE_RANGE(prefix.res, 0, num_res.n);
  res.remaining = PG_SLICE_RANGE_START(prefix.res, num_res.n);
  res.value.end = (u32)(start + s.len - res.remaining.len);

  return res;
}

__attribute((warn_unused_result)) static BencodeValueDecodeResult
bencode_decode_dictionary(PgString s, u32 start, PgAllocator *allocator) {
  BencodeValueDecodeResult res = {
      .value.start = start,
      .value.kind = BENCODE_KIND_DICTIONARY,
  };

  PgStringOk prefix = pg_string_consume_byte(s, 'd');
  if (!prefix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  PgString remaining = prefix.res;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    if ('e' == PG_SLICE_AT(remaining, 0)) {
      break;
    }

    BencodeValueDecodeResult res_key =
        bencode_decode_string(remaining, (u32)(start + s.len - remaining.len));
    if (res_key.err) {
      res.err = res_key.err;
      return res;
    }
    remaining = res_key.remaining;
    PgString key = res_key.value.s;

    // Ensure ordering.
    if (res.value.dict.len > 0) {
      PgString last_key = PG_SLICE_LAST(res.value.dict).key;
      PgStringCompare cmp = pg_string_cmp(last_key, key);
      if (STRING_CMP_LESS != cmp) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }
    }

    // TODO: Address stack overflow.
    BencodeValueDecodeResult res_value = bencode_decode_value(
        remaining, (u32)(start + s.len - remaining.len), allocator);
    if (res_value.err) {
      res.err = res_value.err;
      return res;
    }

    BencodeKeyValue kv = {.key = res_key.value.s, .value = res_value.value};
    // FIXME: Use a `try` version.
    *PG_DYN_PUSH(&res.value.dict, allocator) = kv;

    remaining = res_value.remaining;
  }

  PgStringOk suffix = pg_string_consume_byte(remaining, 'e');
  if (!suffix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }
  res.remaining = suffix.res;
  res.value.end = (u32)(start + s.len - res.remaining.len);

  return res;
}

__attribute((warn_unused_result)) static BencodeValueDecodeResult
bencode_decode_list(PgString s, u32 start, PgAllocator *allocator) {
  BencodeValueDecodeResult res = {
      .value.start = start,
      .value.kind = BENCODE_KIND_LIST,
  };

  PgStringOk prefix = pg_string_consume_byte(s, 'l');
  if (!prefix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  PgString remaining = prefix.res;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      res.err = PG_ERR_INVALID_VALUE;
      return res;
    }
    if ('e' == PG_SLICE_AT(remaining, 0)) {
      break;
    }

    // TODO: Address stack overflow.
    BencodeValueDecodeResult res_value = bencode_decode_value(
        remaining, (u32)(start + s.len - remaining.len), allocator);
    if (res_value.err) {
      res.err = res_value.err;
      return res;
    }

    // FIXME: Use a `try` version.
    *PG_DYN_PUSH(&res.value.list, allocator) = res_value.value;

    remaining = res_value.remaining;
  }

  PgStringOk suffix = pg_string_consume_byte(remaining, 'e');
  if (!suffix.ok) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }
  res.remaining = suffix.res;
  res.value.end = (u32)(start + s.len - res.remaining.len);

  return res;
}

__attribute((warn_unused_result)) static BencodeValueDecodeResult
bencode_decode_value(PgString s, u32 start, PgAllocator *allocator) {
  BencodeValueDecodeResult res = {.value.start = start};

  if (0 == s.len) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }
  switch (PG_SLICE_AT(s, 0)) {
  case 'd': {
    BencodeValueDecodeResult res_dict =
        bencode_decode_dictionary(s, start, allocator);
    if (res_dict.err) {
      res.err = res_dict.err;
      return res;
    }
    res.remaining = res_dict.remaining;
    res.value = res_dict.value;
    return res;
  }
  case 'i': {
    BencodeValueDecodeResult res_num = bencode_decode_number(s, start);
    if (res_num.err) {
      res.err = res_num.err;
      return res;
    }
    res.remaining = res_num.remaining;
    res.value = res_num.value;
    return res;
  }
  case 'l': {
    BencodeValueDecodeResult res_list =
        bencode_decode_list(s, start, allocator);
    if (res_list.err) {
      res.err = res_list.err;
      return res;
    }
    res.remaining = res_list.remaining;
    res.value = res_list.value;
    return res;
  }
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9': {
    BencodeValueDecodeResult res_str = bencode_decode_string(s, start);
    if (res_str.err) {
      res.err = res_str.err;
      return res;
    }
    res.remaining = res_str.remaining;
    res.value = res_str.value;
    return res;
  }
  default:
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }
}

__attribute((warn_unused_result)) __attribute((unused)) static PgError
bencode_encode(BencodeValue value, PgWriter *w, PgAllocator *allocator) {
  PgError err = 0;

  switch (value.kind) {
  case BENCODE_KIND_NUMBER: {
    err = pg_writer_write_u8(w, 'i');
    if (err) {
      return err;
    }

    err = pg_writer_write_u64_as_string(w, value.num);
    if (err) {
      return err;
    }

    err = pg_writer_write_u8(w, 'e');
    if (err) {
      return err;
    }

    break;
  }
  case BENCODE_KIND_STRING: {
    err = pg_writer_write_u64_as_string(w, value.s.len);
    if (err) {
      return err;
    }

    err = pg_writer_write_u8(w, ':');
    if (err) {
      return err;
    }

    err = pg_writer_write_all_string(w, value.s);
    if (err) {
      return err;
    }

    break;
  }
  case BENCODE_KIND_LIST: {
    err = pg_writer_write_u8(w, 'l');
    if (err) {
      return err;
    }

    for (u64 i = 0; i < value.list.len; i++) {
      BencodeValue v = PG_SLICE_AT(value.list, i);
      err = bencode_encode(v, w, allocator);
      if (err) {
        return err;
      }
    }
    err = pg_writer_write_u8(w, 'e');
    if (err) {
      return err;
    }

    break;
  }
  case BENCODE_KIND_DICTIONARY: {
    err = pg_writer_write_u8(w, 'd');
    if (err) {
      return err;
    }

    for (u64 i = 0; i < value.dict.len; i++) {
      BencodeKeyValue kv = PG_SLICE_AT(value.dict, i);
      err = bencode_encode(
          (BencodeValue){.kind = BENCODE_KIND_STRING, .s = kv.key}, w,
          allocator);
      if (err) {
        return err;
      }

      err = bencode_encode(kv.value, w, allocator);
      if (err) {
        return err;
      }

      // Ensure ordering.
      if (i > 0) {
        PgString previous_key = PG_SLICE_AT(value.dict, i - 1).key;
        PgStringCompare cmp = pg_string_cmp(previous_key, kv.key);
        PG_ASSERT(STRING_CMP_LESS == cmp);
      }
    }
    err = pg_writer_write_u8(w, 'e');
    if (err) {
      return err;
    }

    break;
  }
  case BENCODE_KIND_NONE:
  default:
    PG_ASSERT(0);
  }
  return 0;
}

typedef struct {
  PgUrl announce;
  PgString name;
  u64 piece_length;
  PgString pieces;
  u64 length;
  BencodeValueDyn files; // TODO.
  u64 info_start, info_end;
} Metainfo;

PG_RESULT(Metainfo) DecodeMetaInfoResult;

__attribute((unused)) __attribute((warn_unused_result)) static DecodeMetaInfoResult
bencode_decode_metainfo(PgString s, PgAllocator *allocator) {
  DecodeMetaInfoResult res = {0};

  BencodeValueDecodeResult res_dict =
      bencode_decode_dictionary(s, 0, allocator);
  if (res_dict.err) {
    res.err = res_dict.err;
    return res;
  }
  if (0 != res_dict.remaining.len) {
    res.err = PG_ERR_INVALID_VALUE;
    return res;
  }

  BencodeKeyValueDyn dict = res_dict.value.dict;
  for (u64 i = 0; i < dict.len; i++) {
    BencodeKeyValue kv = PG_SLICE_AT(dict, i);

    if (pg_string_eq(kv.key, PG_S("announce"))) {
      if (BENCODE_KIND_STRING != kv.value.kind) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }

      PgUrlResult pg_url_parse_res = pg_url_parse(kv.value.s, allocator);
      if (pg_url_parse_res.err) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }

      res.res.announce = pg_url_parse_res.res;
    } else if (pg_string_eq(kv.key, PG_S("info"))) {
      if (BENCODE_KIND_DICTIONARY != kv.value.kind) {
        res.err = PG_ERR_INVALID_VALUE;
        return res;
      }
      BencodeKeyValueDyn info = kv.value.dict;
      res.res.info_start = kv.value.start;
      res.res.info_end = kv.value.end;

      for (u64 j = 0; j < info.len; j++) {
        BencodeKeyValue info_kv = PG_SLICE_AT(info, j);

        if (pg_string_eq(info_kv.key, PG_S("name"))) {
          if (BENCODE_KIND_STRING != info_kv.value.kind) {
            res.err = PG_ERR_INVALID_VALUE;
            return res;
          }
          res.res.name = info_kv.value.s;
        } else if (pg_string_eq(info_kv.key, PG_S("piece length"))) {
          if (BENCODE_KIND_NUMBER != info_kv.value.kind) {
            res.err = PG_ERR_INVALID_VALUE;
            return res;
          }
          res.res.piece_length = info_kv.value.num;
        } else if (pg_string_eq(info_kv.key, PG_S("pieces"))) {
          if (BENCODE_KIND_STRING != info_kv.value.kind) {
            res.err = PG_ERR_INVALID_VALUE;
            return res;
          }
          res.res.pieces = info_kv.value.s;
        } else if (pg_string_eq(info_kv.key, PG_S("length"))) {
          if (BENCODE_KIND_NUMBER != info_kv.value.kind) {
            res.err = PG_ERR_INVALID_VALUE;
            return res;
          }
          res.res.length = info_kv.value.num;
        }
        // TODO: `files`.
      }
    }
  }

  return res;
}

typedef struct {
  PgArena arena;
  PgLogger *logger;
  Metainfo metainfo;
  PgString file_data;
} TorrentFile;

PG_RESULT(TorrentFile) TorrentFileResult;

__attribute((unused)) __attribute((warn_unused_result)) static TorrentFileResult
torrent_file_read_file(PgString path, Configuration *cfg, PgLogger *logger) {
  TorrentFileResult res = {0};
  char path_c[PG_PATH_MAX] = {0};
  PG_ASSERT(pg_cstr_mut_from_string(path_c, path));

  res.res.logger = logger;

  // Open file
  uv_fs_t req = {0};
  int err_open = uv_fs_open(uv_default_loop(), &req, path_c, UV_FS_O_RDONLY,
                            0600, nullptr);
  if (err_open < 0) {
    pg_log(logger, PG_LOG_LEVEL_ERROR, "failed to open torrent file",
           PG_L("err", err_open),
           PG_L("err_s", pg_cstr_to_string(strerror(err_open))),
           PG_L("path", path));
    res.err = (PgError)err_open;
    goto end;
  }
  uv_file file = err_open;
  PG_ASSERT(file > 0);

  // Get file size.
  int err_stat = uv_fs_fstat(uv_default_loop(), &req, file, nullptr);
  if (err_stat < 0) {
    pg_log(logger, PG_LOG_LEVEL_ERROR, "failed to stat torrent file",
           PG_L("err", err_stat),
           PG_L("err_s", pg_cstr_to_string(strerror(err_stat))),
           PG_L("path", path));
    res.err = (PgError)err_stat;
    goto end;
  }

  // Read entire file.
  u64 file_size = req.statbuf.st_size;
  if (file_size > cfg->torrent_file_max_size) {
    res.err = PG_ERR_TOO_BIG;
    pg_log(logger, PG_LOG_LEVEL_ERROR,
           "torrent file exceeds the maximum allowed size",
           PG_L("err", res.err),
           PG_L("err_s", pg_cstr_to_string(strerror((i32)res.err))),
           PG_L("max", cfg->torrent_file_max_size), PG_L("path", path));
    goto end;
  }
  res.res.arena = pg_arena_make_from_virtual_mem(
      file_size +
      /* bencoding entities */ cfg->torrent_file_max_bencode_alloc_bytes *
          PG_KiB);
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(&res.res.arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  res.res.file_data = pg_string_make(file_size, allocator);
  uv_buf_t buf = string_to_uv_buf(res.res.file_data);
  int err_read = uv_fs_read(uv_default_loop(), &req, file, &buf, 1, 0, nullptr);
  if (err_read < 0) {
    pg_log(logger, PG_LOG_LEVEL_ERROR, "failed to read torrent file",
           PG_L("err", err_read),
           PG_L("err_s", pg_cstr_to_string(strerror(err_read))),
           PG_L("path", path));
    res.err = (PgError)err_read;
    goto end;
  }
  PG_ASSERT(file_size == res.res.file_data.len);

  pg_log(logger, PG_LOG_LEVEL_DEBUG, "read torrent file", PG_L("path", path),
         PG_L("len", res.res.file_data.len));

  // Close file.
  (void)uv_fs_close(uv_default_loop(), &req, file, nullptr);
  uv_fs_req_cleanup(&req);

  // Decode metainfo.
  DecodeMetaInfoResult res_decode_metainfo =
      bencode_decode_metainfo(res.res.file_data, allocator);
  if (res_decode_metainfo.err) {
    pg_log(logger, PG_LOG_LEVEL_ERROR, "failed to decode metainfo",
           PG_L("path", path), PG_L("err", res_decode_metainfo.err),
           PG_L("err_s", PG_S("TODO")));
    res.err = res_decode_metainfo.err;
    goto end;
  }

  res.res.metainfo = res_decode_metainfo.res;

  pg_log(logger, PG_LOG_LEVEL_DEBUG, "decoded torrent file", PG_L("path", path),
         PG_L("mem_use", pg_arena_mem_use(res.res.arena)),
         PG_L("mem_available", pg_arena_mem_available(res.res.arena)));

end:
  if (res.err) {
    (void)pg_arena_release(&res.res.arena);
  }
  return res;
}
