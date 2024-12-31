#pragma once

#include "error.h"
#include "submodules/c-http/http.c"

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
  DynString keys;
  DynBencodeValues values;
} BencodeDictionary;

struct BencodeValue {
  BencodeValueKind kind;
  union {
    u64 num;
    String s;
    DynBencodeValues list;
    BencodeDictionary dict;
  };
};

typedef struct {
  Error err;
  BencodeValue value;
  String remaining;
} BencodeValueDecodeResult;

[[nodiscard]] static BencodeValueDecodeResult
bencode_decode_value(String s, Arena *arena);

typedef struct {
  Error err;
  u64 num;
  String remaining;
} BencodeNumberDecodeResult;

[[nodiscard]] static BencodeNumberDecodeResult bencode_decode_number(String s) {
  BencodeNumberDecodeResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'i');
  if (!prefix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  ParseNumberResult num_res = string_parse_u64(prefix.remaining);
  if (!num_res.present) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  res.num = num_res.n;

  StringConsumeResult suffix = string_consume(num_res.remaining, 'e');
  if (!suffix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  res.remaining = suffix.remaining;
  return res;
}

typedef struct {
  Error err;
  String s;
  String remaining;
} BencodeStringDecodeResult;

[[nodiscard]] static BencodeStringDecodeResult bencode_decode_string(String s) {
  BencodeStringDecodeResult res = {0};

  ParseNumberResult num_res = string_parse_u64(s);
  if (!num_res.present) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  if (0 == num_res.n) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  StringConsumeResult prefix = string_consume(num_res.remaining, ':');
  if (!prefix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  if (prefix.remaining.len < num_res.n) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  res.remaining = prefix.remaining;
  res.s = slice_range(prefix.remaining, 0, num_res.n);
  res.remaining = slice_range(prefix.remaining, num_res.n, 0);

  return res;
}

typedef struct {
  Error err;
  BencodeDictionary dict;
  String remaining;
} BencodeDictionaryDecodeResult;

[[nodiscard]] static BencodeDictionaryDecodeResult
bencode_decode_dictionary(String s, Arena *arena) {
  BencodeDictionaryDecodeResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'd');
  if (!prefix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  String remaining = prefix.remaining;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      res.err = TORR_ERR_BENCODE_INVALID;
      return res;
    }
    if ('e' == slice_at(remaining, 0)) {
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
      String last_key = dyn_last(res.dict.keys);
      StringCompare cmp = string_cmp(last_key, res_key.s);
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

  StringConsumeResult suffix = string_consume(remaining, 'e');
  if (!suffix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  res.remaining = suffix.remaining;

  ASSERT(res.dict.keys.len == res.dict.values.len);

  return res;
}

typedef struct {
  Error err;
  DynBencodeValues values;
  String remaining;
} BencodeListDecodeResult;

[[nodiscard]] static BencodeListDecodeResult bencode_decode_list(String s,
                                                                 Arena *arena) {
  BencodeListDecodeResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'l');
  if (!prefix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }

  String remaining = prefix.remaining;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      res.err = TORR_ERR_BENCODE_INVALID;
      return res;
    }
    if ('e' == slice_at(remaining, 0)) {
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

  StringConsumeResult suffix = string_consume(remaining, 'e');
  if (!suffix.consumed) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  res.remaining = suffix.remaining;

  return res;
}

[[nodiscard]] static BencodeValueDecodeResult
bencode_decode_value(String s, Arena *arena) {
  BencodeValueDecodeResult res = {0};

  if (0 == s.len) {
    res.err = TORR_ERR_BENCODE_INVALID;
    return res;
  }
  switch (slice_at(s, 0)) {
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

static void bencode_encode(BencodeValue value, DynU8 *sb, Arena *arena) {
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
      BencodeValue v = slice_at(value.list, i);
      bencode_encode(v, sb, arena);
    }
    *dyn_push(sb, arena) = 'e';

    break;
  }
  case BENCODE_KIND_DICTIONARY: {
    *dyn_push(sb, arena) = 'd';
    for (u64 i = 0; i < value.dict.keys.len; i++) {
      String k = slice_at(value.dict.keys, i);
      BencodeValue v = slice_at(value.dict.values, i);
      bencode_encode((BencodeValue){.kind = BENCODE_KIND_STRING, .s = k}, sb,
                     arena);
      bencode_encode(v, sb, arena);

      // Ensure ordering.
      if (i > 0) {
        String previous_key = slice_at(value.dict.keys, i - 1);
        StringCompare cmp = string_cmp(previous_key, k);
        ASSERT(STRING_CMP_LESS == cmp);
      }
    }
    *dyn_push(sb, arena) = 'e';

    break;
  }
  case BENCODE_KIND_NONE:
  default:
    ASSERT(0);
  }
}

typedef struct {
  Url announce;
  String name;
  u64 piece_length;
  String pieces;
  u64 length;
  BencodeDictionary files; // TODO.
} Metainfo;

RESULT(Metainfo) DecodeMetaInfoResult;

[[nodiscard]] static DecodeMetaInfoResult decode_metainfo(String s,
                                                          Arena *arena) {
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
    String key = dyn_at(res_dict.dict.keys, i);
    BencodeValue *value = dyn_at_ptr(&res_dict.dict.values, i);

    if (string_eq(key, S("announce"))) {
      if (BENCODE_KIND_STRING != value->kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      ParseUrlResult url_parse_res = url_parse(value->s, arena);
      if (!url_parse_res.ok) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }

      res.res.announce = url_parse_res.url;
    } else if (string_eq(key, S("info"))) {
      if (BENCODE_KIND_DICTIONARY != value->kind) {
        res.err = TORR_ERR_BENCODE_INVALID;
        return res;
      }
      BencodeDictionary *info = &value->dict;

      for (u64 j = 0; j < info->keys.len; j++) {
        String info_key = dyn_at(info->keys, j);
        BencodeValue *info_value = dyn_at_ptr(&info->values, j);

        if (string_eq(info_key, S("name"))) {
          if (BENCODE_KIND_STRING != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.name = info_value->s;
        } else if (string_eq(info_key, S("piece length"))) {
          if (BENCODE_KIND_NUMBER != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.piece_length = info_value->num;
        } else if (string_eq(info_key, S("pieces"))) {
          if (BENCODE_KIND_STRING != info_value->kind) {
            res.err = TORR_ERR_BENCODE_INVALID;
            return res;
          }
          res.res.pieces = info_value->s;
        } else if (string_eq(info_key, S("length"))) {
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
