#pragma once

#include "submodules/cstd/lib.c"

typedef enum {
  BENCODE_KIND_NONE,
  BENCODE_KIND_NUMBER,
  BENCODE_KIND_STRING,
  BENCODE_KIND_ARRAY,
  BENCODE_KIND_DICTIONARY,
} BencodeValueKind;

typedef struct BencodeValue BencodeValue;
typedef struct {
  u64 len;
  BencodeValue *values;
} BencodeSlice;

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
    BencodeSlice array;
    BencodeDictionary dict;
  };
};

typedef enum {
  STATUS_ERR,
  STATUS_OK,
} Status;

typedef struct {
  Status status;
  BencodeValue value;
  String remaining;
} BencodeParseResult;

[[nodiscard]] static BencodeParseResult bencode_parse(String s, Arena *arena);

typedef struct {
  Status status;
  u64 num;
  String remaining;
} BencodeNumberParseResult;

[[nodiscard]] static BencodeNumberParseResult bencode_parse_number(String s) {
  BencodeNumberParseResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'i');
  if (!prefix.consumed) {
    return res;
  }

  ParseNumberResult num_res = string_parse_u64(prefix.remaining);
  if (!num_res.present) {
    return res;
  }

  res.num = num_res.n;

  StringConsumeResult suffix = string_consume(num_res.remaining, 'e');
  if (!suffix.consumed) {
    return res;
  }
  res.remaining = suffix.remaining;
  res.status = STATUS_OK;

  return res;
}

typedef struct {
  Status status;
  String s;
  String remaining;
} BencodeStringParseResult;

[[nodiscard]] static BencodeStringParseResult bencode_parse_string(String s) {
  BencodeStringParseResult res = {0};

  ParseNumberResult num_res = string_parse_u64(s);
  if (!num_res.present) {
    return res;
  }

  if (0 == num_res.n) {
    return res;
  }

  StringConsumeResult prefix = string_consume(num_res.remaining, ':');
  if (!prefix.consumed) {
    return res;
  }

  if (prefix.remaining.len < num_res.n) {
    return res;
  }

  res.remaining = prefix.remaining;
  res.s = slice_range(prefix.remaining, 0, num_res.n);
  res.remaining = slice_range(prefix.remaining, num_res.n, 0);
  res.status = STATUS_OK;

  return res;
}

typedef struct {
  Status status;
  BencodeDictionary dict;
  String remaining;
} BencodeDictionaryParseResult;

[[nodiscard]] static BencodeDictionaryParseResult
bencode_parse_dictionary(String s, Arena *arena) {
  BencodeDictionaryParseResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'd');
  if (!prefix.consumed) {
    return res;
  }

  String remaining = prefix.remaining;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      return res;
    }
    if ('e' == slice_at(remaining, 0)) {
      break;
    }

    BencodeStringParseResult res_key = bencode_parse_string(remaining);
    if (STATUS_OK != res_key.status) {
      return res;
    }
    remaining = res_key.remaining;
    *dyn_push(&res.dict.keys, arena) = res_key.s;

    // TODO: Address stack overflow.
    BencodeParseResult res_value = bencode_parse(remaining, arena);
    if (STATUS_OK != res_value.status) {
      return res;
    }

    *dyn_push(&res.dict.values, arena) = res_value.value;

    remaining = res_value.remaining;
  }

  StringConsumeResult suffix = string_consume(remaining, 'e');
  if (!suffix.consumed) {
    return res;
  }
  res.remaining = suffix.remaining;
  res.status = STATUS_OK;

  ASSERT(res.dict.keys.len == res.dict.values.len);

  return res;
}

typedef struct {
  Status status;
  DynBencodeValues values;
  String remaining;
} BencodeListParseResult;

[[nodiscard]] static BencodeListParseResult bencode_parse_list(String s,
                                                               Arena *arena) {
  BencodeListParseResult res = {0};

  StringConsumeResult prefix = string_consume(s, 'l');
  if (!prefix.consumed) {
    return res;
  }

  String remaining = prefix.remaining;
  for (u64 lim = 0; lim < remaining.len; lim++) {
    if (0 == remaining.len) {
      return res;
    }
    if ('e' == slice_at(remaining, 0)) {
      break;
    }

    // TODO: Address stack overflow.
    BencodeParseResult res_value = bencode_parse(remaining, arena);
    if (STATUS_OK != res_value.status) {
      return res;
    }

    *dyn_push(&res.values, arena) = res_value.value;

    remaining = res_value.remaining;
  }

  StringConsumeResult suffix = string_consume(remaining, 'e');
  if (!suffix.consumed) {
    return res;
  }
  res.remaining = suffix.remaining;
  res.status = STATUS_OK;

  return res;
}

[[nodiscard]] static BencodeParseResult bencode_parse(String s, Arena *arena) {
  BencodeParseResult res = {0};

  if (0 == s.len) {
    return res;
  }
  switch (slice_at(s, 0)) {
  case 'd': {
    BencodeDictionaryParseResult res_dict = bencode_parse_dictionary(s, arena);
    if (STATUS_OK != res_dict.status) {
      return res;
    }
    res.remaining = res_dict.remaining;
    res.status = STATUS_OK;
    res.value.kind = BENCODE_KIND_DICTIONARY;
    res.value.dict = res_dict.dict;
    return res;
  }
  case 'i': {
    BencodeNumberParseResult res_num = bencode_parse_number(s);
    if (STATUS_OK != res_num.status) {
      return res;
    }
    res.status = STATUS_OK;
    res.remaining = res_num.remaining;
    res.value.kind = BENCODE_KIND_NUMBER;
    res.value.num = res_num.num;
    return res;
  }
  case 'l': {
    ASSERT(false && "TODO");
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
    BencodeStringParseResult res_str = bencode_parse_string(s);
    if (STATUS_OK != res_str.status) {
      return res;
    }
    res.status = STATUS_OK;
    res.remaining = res_str.remaining;
    res.value.kind = BENCODE_KIND_STRING;
    res.value.s = res_str.s;
    return res;
  }
  default:
    return res;
  }
}

typedef struct {
  String announce;
  String name;
  u64 piece_length;
  String pieces;
  u64 length;
  BencodeDictionary files; // TODO.
} Metainfo;

typedef struct {
  Status status;
  Metainfo metainfo;
} ParseMetaInfoResult;

#if 0
[[nodiscard]] static ParseMetaInfoResult parse_metainfo(String s) {
  ParseMetaInfoResult res = {0};

  return res;
}
#endif
