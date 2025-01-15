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
      PgString last_key = dyn_last(res.dict.keys);
      StringCompare cmp = pg_string_cmp(last_key, res_key.s);
      if (STRING_CMP_LESS != cmp) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
    }

    *dyn_push(&res.dict.keys, arena) = res_key.s;

    // TODO: Address stack overflow.
    BencodeValueDecodeResult res_value = bencode_decode_value(remaining, arena);
    if (res_value.err) {
      res.err = res_value.err;
      return res;
    }

    *dyn_push(&res.dict.values, arena) = res_value.value;

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

[[nodiscard]] static BencodeListDecodeResult bencode_decode_list(PgString s,
                                                                 PgArena *arena) {
  BencodeListDecodeResult res = {0};

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

    *dyn_push(&res.values, arena) = res_value.value;

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

[[maybe_unused]]
static void bencode_encode(BencodeValue value, Pgu8Dyn *sb, PgArena *arena) {
  switch (value.kind) {
  case BENCODE_KIND_NUMBER: {
    *dyn_push(sb, arena) = 'i';
    dynu8_append_u64_to_string(sb, value.num, arena);
    *dyn_push(sb, arena) = 'e';

    break;
  }
  case BENCODE_KIND_STRING: {
    dynu8_append_u64_to_string(sb, value.s.len, arena);
    *dyn_push(sb, arena) = ':';
    dyn_append_slice(sb, value.s, arena);

    break;
  }
  case BENCODE_KIND_LIST: {
    *dyn_push(sb, arena) = 'l';
    for (u64 i = 0; i < value.list.len; i++) {
      BencodeValue v = PG_SLICE_AT(value.list, i);
      bencode_encode(v, sb, arena);
    }
    *dyn_push(sb, arena) = 'e';

    break;
  }
  case BENCODE_KIND_DICTIONARY: {
    *dyn_push(sb, arena) = 'd';
    for (u64 i = 0; i < value.dict.keys.len; i++) {
      PgString k = PG_SLICE_AT(value.dict.keys, i);
      BencodeValue v = PG_SLICE_AT(value.dict.values, i);
      bencode_encode((BencodeValue){.kind = BENCODE_KIND_STRING, .s = k}, sb,
                     arena);
      bencode_encode(v, sb, arena);

      // Ensure ordering.
      if (i > 0) {
        PgString previous_key = PG_SLICE_AT(value.dict.keys, i - 1);
        StringCompare cmp = pg_string_cmp(previous_key, k);
        PG_ASSERT(STRING_CMP_LESS == cmp);
      }
    }
    *dyn_push(sb, arena) = 'e';

    break;
  }
  case BENCODE_KIND_NONE:
  default:
    PG_ASSERT(0);
  }
}

typedef struct {
  Url announce;
  PgString name;
  u64 piece_length;
  PgString pieces;
  u64 length;
  BencodeDictionary files; // TODO.
} Metainfo;

PG_RESULT(Metainfo) DecodeMetaInfoResult;

[[nodiscard]] static DecodeMetaInfoResult
bencode_decode_metainfo(PgString s, PgArena *arena) {
  DecodeMetaInfoResult res = {0};

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
    PgString key = dyn_at(res_dict.dict.keys, i);
    BencodeValue *value = dyn_at_ptr(&res_dict.dict.values, i);

    if (pg_string_eq(key, PG_S("announce"))) {
      if (BENCODE_KIND_STRING != value->kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      PgUrlResult url_parse_res = url_parse(value->s, arena);
      if (url_parse_res.err) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      res.res.announce = url_parse_res.res;
    } else if (pg_string_eq(key, PG_S("info"))) {
      if (BENCODE_KIND_DICTIONARY != value->kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
      BencodeDictionary *info = &value->dict;

      for (u64 j = 0; j < info->keys.len; j++) {
        PgString info_key = dyn_at(info->keys, j);
        BencodeValue *info_value = dyn_at_ptr(&info->values, j);

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
