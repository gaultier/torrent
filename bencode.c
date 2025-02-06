#pragma once

#include "error.h"
#include "submodules/cstd/lib.c"

typedef enum {
  BENCODE_KIND_NONE,
  BENCODE_KIND_NUMBER,
  BENCODE_KIND_STRING,
  BENCODE_KIND_LIST,
  BENCODE_KIND_DICTIONARY,
} BencodeValueKind;

typedef struct BencodeValue BencodeValue;

typedef struct {
  BencodeValue *data;
  u64 len, cap;
} DynBencodeValues;

typedef struct {
  PgStringDyn keys;
  DynBencodeValues values;
} BencodeDictionary;

struct BencodeValue {
  BencodeValueKind kind;
  union {
    u64 num;
    PgString s;
    DynBencodeValues list;
    BencodeDictionary dict;
  };
};

typedef struct {
  PgError err;
  BencodeValue value;
  PgString remaining;
} BencodeValueDecodeResult;

[[nodiscard]] static BencodeValueDecodeResult
bencode_decode_value(PgString s, PgArena *arena);

typedef struct {
  PgError err;
  u64 num;
  PgString remaining;
} BencodeNumberDecodeResult;

[[nodiscard]] static BencodeNumberDecodeResult
bencode_decode_number(PgString s) {
  BencodeNumberDecodeResult res = {0};

  PgStringOk prefix = pg_string_consume_byte(s, 'i');
  if (!prefix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  PgParseNumberResult num_res = pg_string_parse_u64(prefix.res);
  if (!num_res.present) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  res.num = num_res.n;

  PgStringOk suffix = pg_string_consume_byte(num_res.remaining, 'e');
  if (!suffix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  res.remaining = suffix.res;
  return res;
}

typedef struct {
  PgError err;
  PgString s;
  PgString remaining;
} BencodeStringDecodeResult;

[[nodiscard]] static BencodeStringDecodeResult
bencode_decode_string(PgString s) {
  BencodeStringDecodeResult res = {0};

  PgParseNumberResult num_res = pg_string_parse_u64(s);
  if (!num_res.present) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  if (0 == num_res.n) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  PgStringOk prefix = pg_string_consume_byte(num_res.remaining, ':');
  if (!prefix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  if (prefix.res.len < num_res.n) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  res.s = PG_SLICE_RANGE(prefix.res, 0, num_res.n);
  res.remaining = PG_SLICE_RANGE_START(prefix.res, num_res.n);

  return res;
}

typedef struct {
  PgError err;
  BencodeDictionary dict;
  PgString remaining;
} BencodeDictionaryDecodeResult;

[[nodiscard]] static BencodeDictionaryDecodeResult
bencode_decode_dictionary(PgString s, PgArena *arena) {
  BencodeDictionaryDecodeResult res = {0};
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  PgStringOk prefix = pg_string_consume_byte(s, 'd');
  if (!prefix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  PgString remaining = prefix.res;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      res.err = TORR_ERR_BENCODE_INVALID;
      return res;
    }
    if ('e' == PG_SLICE_AT(remaining, 0)) {
      break;
    }

    BencodeStringDecodeResult res_key = bencode_decode_string(remaining);
    if (res_key.err) {
      res.err = res_key.err;
      return res;
    }
    remaining = res_key.remaining;

    // Ensure ordering.
    if (res.dict.keys.len > 0) {
      PgString last_key = PG_SLICE_LAST(res.dict.keys);
      PgStringCompare cmp = pg_string_cmp(last_key, res_key.s);
      if (STRING_CMP_LESS != cmp) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
    }

    *PG_DYN_PUSH(&res.dict.keys, allocator) = res_key.s;

    // TODO: Address stack overflow.
    BencodeValueDecodeResult res_value = bencode_decode_value(remaining, arena);
    if (res_value.err) {
      res.err = res_value.err;
      return res;
    }

    *PG_DYN_PUSH(&res.dict.values, allocator) = res_value.value;

    remaining = res_value.remaining;
  }

  PgStringOk suffix = pg_string_consume_byte(remaining, 'e');
  if (!suffix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  res.remaining = suffix.res;

  PG_ASSERT(res.dict.keys.len == res.dict.values.len);

  return res;
}

typedef struct {
  PgError err;
  DynBencodeValues values;
  PgString remaining;
} BencodeListDecodeResult;

[[nodiscard]] static BencodeListDecodeResult
bencode_decode_list(PgString s, PgArena *arena) {
  BencodeListDecodeResult res = {0};
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  PgStringOk prefix = pg_string_consume_byte(s, 'l');
  if (!prefix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  PgString remaining = prefix.res;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      res.err = TORR_ERR_BENCODE_INVALID;
      return res;
    }
    if ('e' == PG_SLICE_AT(remaining, 0)) {
      break;
    }

    // TODO: Address stack overflow.
    BencodeValueDecodeResult res_value = bencode_decode_value(remaining, arena);
    if (res_value.err) {
      res.err = res_value.err;
      return res;
    }

    *PG_DYN_PUSH(&res.values, allocator) = res_value.value;

    remaining = res_value.remaining;
  }

  PgStringOk suffix = pg_string_consume_byte(remaining, 'e');
  if (!suffix.ok) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  res.remaining = suffix.res;

  return res;
}

[[nodiscard]] static BencodeValueDecodeResult
bencode_decode_value(PgString s, PgArena *arena) {
  BencodeValueDecodeResult res = {0};

  if (0 == s.len) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  switch (PG_SLICE_AT(s, 0)) {
  case 'd': {
    BencodeDictionaryDecodeResult res_dict =
        bencode_decode_dictionary(s, arena);
    if (res_dict.err) {
      res.err = res_dict.err;
      return res;
    }
    res.remaining = res_dict.remaining;
    res.value.kind = BENCODE_KIND_DICTIONARY;
    res.value.dict = res_dict.dict;
    return res;
  }
  case 'i': {
    BencodeNumberDecodeResult res_num = bencode_decode_number(s);
    if (res_num.err) {
      res.err = res_num.err;
      return res;
    }
    res.remaining = res_num.remaining;
    res.value.kind = BENCODE_KIND_NUMBER;
    res.value.num = res_num.num;
    return res;
  }
  case 'l': {
    BencodeListDecodeResult res_list = bencode_decode_list(s, arena);
    if (res_list.err) {
      res.err = res_list.err;
      return res;
    }
    res.remaining = res_list.remaining;
    res.value.kind = BENCODE_KIND_LIST;
    res.value.list = res_list.values;
    return res;
  }
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9': {
    BencodeStringDecodeResult res_str = bencode_decode_string(s);
    if (res_str.err) {
      res.err = res_str.err;
      return res;
    }
    res.remaining = res_str.remaining;
    res.value.kind = BENCODE_KIND_STRING;
    res.value.s = res_str.s;
    return res;
  }
  default:
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
}

[[nodiscard]] [[maybe_unused]] static PgError
bencode_encode(BencodeValue value, PgWriter *w, PgArena *arena) {
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
      err = bencode_encode(v, w, arena);
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

    for (u64 i = 0; i < value.dict.keys.len; i++) {
      PgString k = PG_SLICE_AT(value.dict.keys, i);
      BencodeValue v = PG_SLICE_AT(value.dict.values, i);
      err = bencode_encode((BencodeValue){.kind = BENCODE_KIND_STRING, .s = k},
                           w, arena);
      if (err) {
        return err;
      }

      err = bencode_encode(v, w, arena);
      if (err) {
        return err;
      }

      // Ensure ordering.
      if (i > 0) {
        PgString previous_key = PG_SLICE_AT(value.dict.keys, i - 1);
        PgStringCompare cmp = pg_string_cmp(previous_key, k);
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
  BencodeDictionary files; // TODO.
} Metainfo;

PG_RESULT(Metainfo) DecodeMetaInfoResult;

[[maybe_unused]] [[nodiscard]] static DecodeMetaInfoResult
bencode_decode_metainfo(PgString s, PgArena *arena) {
  DecodeMetaInfoResult res = {0};
  PgArenaAllocator arena_allocator = pg_make_arena_allocator(arena);
  PgAllocator *allocator = pg_arena_allocator_as_allocator(&arena_allocator);

  BencodeDictionaryDecodeResult res_dict = bencode_decode_dictionary(s, arena);
  if (res_dict.err) {
    res.err = res_dict.err;
    return res;
  }
  if (0 != res_dict.remaining.len) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  for (u64 i = 0; i < res_dict.dict.keys.len; i++) {
    PgString key = PG_SLICE_AT(res_dict.dict.keys, i);
    BencodeValue *value = PG_SLICE_AT_PTR(&res_dict.dict.values, i);

    if (pg_string_eq(key, PG_S("announce"))) {
      if (BENCODE_KIND_STRING != value->kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      PgUrlResult pg_url_parse_res = pg_url_parse(value->s, allocator);
      if (pg_url_parse_res.err) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      res.res.announce = pg_url_parse_res.res;
    } else if (pg_string_eq(key, PG_S("info"))) {
      if (BENCODE_KIND_DICTIONARY != value->kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
      BencodeDictionary *info = &value->dict;

      for (u64 j = 0; j < info->keys.len; j++) {
        PgString info_key = PG_SLICE_AT(info->keys, j);
        BencodeValue *info_value = PG_SLICE_AT_PTR(&info->values, j);

        if (pg_string_eq(info_key, PG_S("name"))) {
          if (BENCODE_KIND_STRING != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.name = info_value->s;
        } else if (pg_string_eq(info_key, PG_S("piece length"))) {
          if (BENCODE_KIND_NUMBER != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.piece_length = info_value->num;
        } else if (pg_string_eq(info_key, PG_S("pieces"))) {
          if (BENCODE_KIND_STRING != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.pieces = info_value->s;
        } else if (pg_string_eq(info_key, PG_S("length"))) {
          if (BENCODE_KIND_NUMBER != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.length = info_value->num;
        }
        // TODO: `files`.
      }
    }
  }

  return res;
}
